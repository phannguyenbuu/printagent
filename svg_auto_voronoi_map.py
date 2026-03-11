"""
Install:
    pip install numpy scipy shapely

Optional for better SVG curve sampling:
    pip install svgpathtools

Run:
    python svg_auto_voronoi_map.py
"""

from __future__ import annotations

import json
import math
import random
import re
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from uuid import uuid4

import numpy as np
from flask import Flask, render_template_string, request, send_from_directory, url_for
from scipy.spatial import Voronoi, cKDTree
from shapely import concave_hull
from shapely.geometry import GeometryCollection, LineString, MultiPoint, MultiPolygon, Point, Polygon
from shapely.geometry.polygon import orient
from shapely.ops import polygonize, unary_union

try:
    from svgpathtools import parse_path as svg_parse_path
except Exception:
    svg_parse_path = None


DEFAULT_TARGET_COUNT = 110
DEFAULT_MIN_COUNT = 100
DEFAULT_MAX_COUNT = 120
DEFAULT_ITERATIONS = 40
DEFAULT_SNAP_K = 5
DEFAULT_SMALL_THRESHOLD = 0.75
DEFAULT_LARGE_THRESHOLD = 1.25
POINT_MERGE_TOL = 0.75
COLLINEAR_EPS = 1e-6
MIN_POLYGON_AREA = 1e-4
APP_ROOT = Path(__file__).resolve().parent
FLASK_WORK_DIR = APP_ROOT / "tool_extract" / "flask_debug"
UPLOAD_DIR = FLASK_WORK_DIR / "uploads"
RUNS_DIR = FLASK_WORK_DIR / "runs"


@dataclass
class SvgGeometry:
    path: Path
    root: ET.Element
    tree: ET.ElementTree
    view_box: tuple[float, float, float, float]
    candidate_polygons: list[Polygon] = field(default_factory=list)
    line_strings: list[LineString] = field(default_factory=list)
    all_vertices: list[tuple[float, float]] = field(default_factory=list)
    snap_vertices: list[tuple[float, float]] = field(default_factory=list)
    outline_segments: list[tuple[tuple[float, float], tuple[float, float]]] = field(default_factory=list)


@dataclass
class AreaStats:
    count: int
    average: float
    minimum: float
    maximum: float
    std_area: float
    outlier_count: int
    too_small_count: int
    too_large_count: int


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except Exception:
        return default
    return result if math.isfinite(result) else default


def fmt_num(value: float) -> str:
    text = f"{value:.6f}".rstrip("0").rstrip(".")
    return text or "0"


def parse_svg_length(value: Optional[str], fallback: float) -> float:
    if not value:
        return fallback
    match = re.search(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", value)
    return safe_float(match.group(0), fallback) if match else fallback


def log_exception_text() -> str:
    return traceback.format_exc(limit=10)


def unique_points(points: Iterable[tuple[float, float]], tol: float = POINT_MERGE_TOL) -> list[tuple[float, float]]:
    cell_size = max(tol, 1e-6)
    buckets: dict[tuple[int, int], list[tuple[float, float]]] = {}
    result: list[tuple[float, float]] = []
    for x, y in points:
        gx = int(math.floor(x / cell_size))
        gy = int(math.floor(y / cell_size))
        duplicate = False
        for ix in range(gx - 1, gx + 2):
            for iy in range(gy - 1, gy + 2):
                for px, py in buckets.get((ix, iy), []):
                    if (x - px) ** 2 + (y - py) ** 2 <= tol * tol:
                        duplicate = True
                        break
                if duplicate:
                    break
            if duplicate:
                break
        if not duplicate:
            pt = (float(x), float(y))
            result.append(pt)
            buckets.setdefault((gx, gy), []).append(pt)
    return result


def nearly_collinear(
    a: tuple[float, float],
    b: tuple[float, float],
    c: tuple[float, float],
    eps: float = COLLINEAR_EPS,
) -> bool:
    area2 = abs((b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]))
    scale = max(1.0, math.dist(a, b) + math.dist(b, c))
    return area2 <= eps * scale


def simplify_ring_points(points: list[tuple[float, float]], closed: bool = True) -> list[tuple[float, float]]:
    if not points:
        return []
    cleaned: list[tuple[float, float]] = []
    for point in points:
        if not cleaned or math.dist(cleaned[-1], point) > POINT_MERGE_TOL * 0.25:
            cleaned.append(point)
    if closed and len(cleaned) > 2 and math.dist(cleaned[0], cleaned[-1]) <= POINT_MERGE_TOL * 0.25:
        cleaned.pop()
    changed = True
    while changed and len(cleaned) >= 3:
        changed = False
        next_points: list[tuple[float, float]] = []
        total = len(cleaned)
        for index, point in enumerate(cleaned):
            prev_point = cleaned[(index - 1) % total] if closed else cleaned[max(0, index - 1)]
            next_point = cleaned[(index + 1) % total] if closed else cleaned[min(total - 1, index + 1)]
            if total > 2 and nearly_collinear(prev_point, point, next_point):
                changed = True
                continue
            next_points.append(point)
        if len(next_points) >= 3:
            cleaned = next_points
    return cleaned


def clean_polygon(polygon: Polygon) -> Optional[Polygon]:
    if polygon is None or polygon.is_empty:
        return None
    current: Any = polygon if polygon.is_valid else polygon.buffer(0)
    if current.is_empty:
        return None
    if isinstance(current, MultiPolygon):
        current = max(current.geoms, key=lambda geom: geom.area, default=None)
    if current is None or current.is_empty or current.area <= MIN_POLYGON_AREA:
        return None
    points = simplify_ring_points([(float(x), float(y)) for x, y in current.exterior.coords[:-1]], closed=True)
    if len(points) < 3:
        return None
    current = Polygon(points)
    current = current if current.is_valid else current.buffer(0)
    if current.is_empty:
        return None
    if isinstance(current, MultiPolygon):
        current = max(current.geoms, key=lambda geom: geom.area, default=None)
    if current is None or current.is_empty or current.area <= MIN_POLYGON_AREA:
        return None
    return orient(current, sign=1.0)


def flatten_polygons(geometry: Any) -> list[Polygon]:
    if geometry is None or geometry.is_empty:
        return []
    if isinstance(geometry, Polygon):
        return [orient(geometry, sign=1.0)]
    if isinstance(geometry, MultiPolygon):
        return [orient(item, sign=1.0) for item in geometry.geoms if not item.is_empty and item.area > MIN_POLYGON_AREA]
    if isinstance(geometry, GeometryCollection):
        output: list[Polygon] = []
        for item in geometry.geoms:
            output.extend(flatten_polygons(item))
        return output
    return []


def polygon_from_points(points: Iterable[tuple[float, float]]) -> Optional[Polygon]:
    clean_points = simplify_ring_points(list(points), closed=True)
    if len(clean_points) < 3:
        return None
    return clean_polygon(Polygon(clean_points))


def polygon_points(polygon: Polygon) -> list[tuple[float, float]]:
    return [(float(x), float(y)) for x, y in polygon.exterior.coords[:-1]]


def polygon_with_points(points: list[tuple[float, float]]) -> Optional[Polygon]:
    if len(points) < 3:
        return None
    return clean_polygon(Polygon(points))


def parse_transform(transform: Optional[str]) -> np.ndarray:
    if not transform:
        return np.eye(3)
    matrix = np.eye(3)
    for name, args_text in re.findall(r"([a-zA-Z]+)\s*\(([^)]*)\)", transform):
        args = [safe_float(part) for part in re.split(r"[,\s]+", args_text.strip()) if part.strip()]
        op = np.eye(3)
        name = name.lower()
        if name == "translate":
            tx = args[0] if args else 0.0
            ty = args[1] if len(args) > 1 else 0.0
            op = np.array([[1.0, 0.0, tx], [0.0, 1.0, ty], [0.0, 0.0, 1.0]])
        elif name == "scale":
            sx = args[0] if args else 1.0
            sy = args[1] if len(args) > 1 else sx
            op = np.array([[sx, 0.0, 0.0], [0.0, sy, 0.0], [0.0, 0.0, 1.0]])
        elif name == "rotate":
            angle = math.radians(args[0] if args else 0.0)
            cos_v = math.cos(angle)
            sin_v = math.sin(angle)
            rotation = np.array([[cos_v, -sin_v, 0.0], [sin_v, cos_v, 0.0], [0.0, 0.0, 1.0]])
            if len(args) >= 3:
                cx, cy = args[1], args[2]
                t1 = np.array([[1.0, 0.0, cx], [0.0, 1.0, cy], [0.0, 0.0, 1.0]])
                t2 = np.array([[1.0, 0.0, -cx], [0.0, 1.0, -cy], [0.0, 0.0, 1.0]])
                op = t1 @ rotation @ t2
            else:
                op = rotation
        elif name == "matrix" and len(args) >= 6:
            a, b, c, d, e, f = args[:6]
            op = np.array([[a, c, e], [b, d, f], [0.0, 0.0, 1.0]])
        matrix = matrix @ op
    return matrix


def apply_matrix(points: Iterable[tuple[float, float]], matrix: np.ndarray) -> list[tuple[float, float]]:
    transformed: list[tuple[float, float]] = []
    for x, y in points:
        vector = matrix @ np.array([x, y, 1.0], dtype=float)
        transformed.append((float(vector[0]), float(vector[1])))
    return transformed


def parse_points_attr(text: Optional[str]) -> list[tuple[float, float]]:
    if not text:
        return []
    tokens = re.split(r"[,\s]+", text.strip())
    values = [safe_float(token) for token in tokens if token.strip()]
    return [(values[index], values[index + 1]) for index in range(0, len(values) - 1, 2)]


def parse_line_element(element: ET.Element, matrix: np.ndarray) -> list[tuple[float, float]]:
    points = [
        (safe_float(element.get("x1")), safe_float(element.get("y1"))),
        (safe_float(element.get("x2")), safe_float(element.get("y2"))),
    ]
    return apply_matrix(points, matrix)


def parse_poly_element(element: ET.Element, matrix: np.ndarray) -> list[tuple[float, float]]:
    return apply_matrix(parse_points_attr(element.get("points")), matrix)


def fallback_parse_path_points(path_d: str) -> list[list[tuple[float, float]]]:
    if not path_d:
        return []
    tokens = re.findall(r"[AaCcHhLlMmQqSsTtVvZz]|[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", path_d)
    if not tokens:
        return []
    paths: list[list[tuple[float, float]]] = []
    current: list[tuple[float, float]] = []
    cursor = (0.0, 0.0)
    start = (0.0, 0.0)
    index = 0
    command = "M"

    def append_point(point: tuple[float, float]) -> None:
        nonlocal current
        if not current or math.dist(current[-1], point) > 1e-9:
            current.append(point)

    while index < len(tokens):
        token = tokens[index]
        if re.fullmatch(r"[AaCcHhLlMmQqSsTtVvZz]", token):
            command = token
            index += 1
            if command in "Zz":
                if current and current[0] != current[-1]:
                    current.append(current[0])
                if current:
                    paths.append(current)
                current = []
                cursor = start
            continue
        if command in "Mm":
            x = safe_float(tokens[index])
            y = safe_float(tokens[index + 1]) if index + 1 < len(tokens) else 0.0
            index += 2
            cursor = (cursor[0] + x, cursor[1] + y) if command == "m" else (x, y)
            start = cursor
            if current:
                paths.append(current)
            current = [cursor]
            command = "L" if command == "M" else "l"
        elif command in "Ll":
            x = safe_float(tokens[index])
            y = safe_float(tokens[index + 1]) if index + 1 < len(tokens) else 0.0
            index += 2
            cursor = (cursor[0] + x, cursor[1] + y) if command == "l" else (x, y)
            append_point(cursor)
        elif command in "Hh":
            x = safe_float(tokens[index])
            index += 1
            cursor = (cursor[0] + x, cursor[1]) if command == "h" else (x, cursor[1])
            append_point(cursor)
        elif command in "Vv":
            y = safe_float(tokens[index])
            index += 1
            cursor = (cursor[0], cursor[1] + y) if command == "v" else (cursor[0], y)
            append_point(cursor)
        elif command in "Cc":
            if index + 5 >= len(tokens):
                break
            x1 = safe_float(tokens[index])
            y1 = safe_float(tokens[index + 1])
            x2 = safe_float(tokens[index + 2])
            y2 = safe_float(tokens[index + 3])
            x3 = safe_float(tokens[index + 4])
            y3 = safe_float(tokens[index + 5])
            index += 6
            if command == "c":
                p1 = (cursor[0] + x1, cursor[1] + y1)
                p2 = (cursor[0] + x2, cursor[1] + y2)
                p3 = (cursor[0] + x3, cursor[1] + y3)
            else:
                p1 = (x1, y1)
                p2 = (x2, y2)
                p3 = (x3, y3)
            for step in range(1, 13):
                t = step / 12.0
                mt = 1.0 - t
                px = (
                    mt * mt * mt * cursor[0]
                    + 3.0 * mt * mt * t * p1[0]
                    + 3.0 * mt * t * t * p2[0]
                    + t * t * t * p3[0]
                )
                py = (
                    mt * mt * mt * cursor[1]
                    + 3.0 * mt * mt * t * p1[1]
                    + 3.0 * mt * t * t * p2[1]
                    + t * t * t * p3[1]
                )
                append_point((px, py))
            cursor = p3
        elif command in "Qq":
            if index + 3 >= len(tokens):
                break
            x1 = safe_float(tokens[index])
            y1 = safe_float(tokens[index + 1])
            x2 = safe_float(tokens[index + 2])
            y2 = safe_float(tokens[index + 3])
            index += 4
            if command == "q":
                p1 = (cursor[0] + x1, cursor[1] + y1)
                p2 = (cursor[0] + x2, cursor[1] + y2)
            else:
                p1 = (x1, y1)
                p2 = (x2, y2)
            for step in range(1, 13):
                t = step / 12.0
                mt = 1.0 - t
                px = mt * mt * cursor[0] + 2.0 * mt * t * p1[0] + t * t * p2[0]
                py = mt * mt * cursor[1] + 2.0 * mt * t * p1[1] + t * t * p2[1]
                append_point((px, py))
            cursor = p2
        elif command in "Aa":
            if index + 6 >= len(tokens):
                break
            x = safe_float(tokens[index + 5])
            y = safe_float(tokens[index + 6])
            index += 7
            cursor = (cursor[0] + x, cursor[1] + y) if command == "a" else (x, y)
            append_point(cursor)
        elif command in "SsTt":
            pairs = 4 if command in "Ss" else 2
            if index + pairs - 1 >= len(tokens):
                break
            values = [safe_float(tokens[index + offset]) for offset in range(pairs)]
            index += pairs
            if command in "Ss":
                x = values[2]
                y = values[3]
            else:
                x = values[0]
                y = values[1]
            cursor = (cursor[0] + x, cursor[1] + y) if command.islower() else (x, y)
            append_point(cursor)
        else:
            break

    if current:
        paths.append(current)
    return [path for path in paths if len(path) >= 2]


def parse_path_points(path_d: str, matrix: np.ndarray) -> list[list[tuple[float, float]]]:
    sampled_paths: list[list[tuple[float, float]]] = []
    if svg_parse_path is not None:
        try:
            path = svg_parse_path(path_d)
            current_points: list[tuple[float, float]] = []
            for segment in path:
                try:
                    segment_length = max(float(segment.length(error=1e-3)), 2.0)
                except Exception:
                    segment_length = 10.0
                samples = max(2, int(segment_length / 8.0))
                for sample_index in range(samples + 1):
                    pt = segment.point(sample_index / samples)
                    xy = (float(pt.real), float(pt.imag))
                    if not current_points or math.dist(current_points[-1], xy) > 1e-6:
                        current_points.append(xy)
            if current_points:
                sampled_paths = [current_points]
        except Exception:
            sampled_paths = []
    if not sampled_paths:
        sampled_paths = fallback_parse_path_points(path_d)
    return [apply_matrix(points, matrix) for points in sampled_paths if len(points) >= 2]


def element_has_listvertex_hint(element: ET.Element) -> bool:
    for key, value in element.attrib.items():
        if key.lower() in {"id", "class", "name"} and isinstance(value, str) and "listvertex" in value.lower():
            return True
        if isinstance(value, str) and "listvertex" in value.lower():
            return True
    return False


def add_segments(
    points: list[tuple[float, float]],
    closed: bool,
    collector: list[tuple[tuple[float, float], tuple[float, float]]],
) -> None:
    if len(points) < 2:
        return
    limit = len(points) if closed else len(points) - 1
    for index in range(limit):
        a = points[index]
        b = points[(index + 1) % len(points)]
        if math.dist(a, b) > 1e-9:
            collector.append((a, b))


def extract_vertices(geometry: SvgGeometry) -> list[tuple[float, float]]:
    return unique_points(geometry.snap_vertices or geometry.all_vertices, tol=POINT_MERGE_TOL)


def load_svg(svg_path: Path) -> SvgGeometry:
    try:
        tree = ET.parse(svg_path)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid SVG XML: {exc}") from exc

    root = tree.getroot()
    vb_attr = root.get("viewBox")
    width = parse_svg_length(root.get("width"), 1000.0)
    height = parse_svg_length(root.get("height"), 1000.0)
    if vb_attr:
        parts = [safe_float(part) for part in re.split(r"[,\s]+", vb_attr.strip()) if part.strip()]
        view_box = (parts[0], parts[1], parts[2], parts[3]) if len(parts) == 4 else (0.0, 0.0, width, height)
    else:
        view_box = (0.0, 0.0, width, height)

    candidate_polygons: list[Polygon] = []
    line_strings: list[LineString] = []
    all_vertices: list[tuple[float, float]] = []
    snap_vertices: list[tuple[float, float]] = []
    outline_segments: list[tuple[tuple[float, float], tuple[float, float]]] = []

    def walk(node: ET.Element, parent_matrix: np.ndarray) -> None:
        matrix = parent_matrix @ parse_transform(node.get("transform"))
        tag = node.tag.rsplit("}", 1)[-1].lower()
        listvertex_hint = element_has_listvertex_hint(node)
        if tag == "polygon":
            points = parse_poly_element(node, matrix)
            all_vertices.extend(points)
            add_segments(points, True, outline_segments)
            polygon = polygon_from_points(points)
            if polygon is not None:
                candidate_polygons.append(polygon)
            if listvertex_hint:
                snap_vertices.extend(points)
        elif tag == "polyline":
            points = parse_poly_element(node, matrix)
            all_vertices.extend(points)
            add_segments(points, False, outline_segments)
            if len(points) >= 2:
                line_strings.append(LineString(points))
            if len(points) >= 3 and math.dist(points[0], points[-1]) <= POINT_MERGE_TOL:
                polygon = polygon_from_points(points)
                if polygon is not None:
                    candidate_polygons.append(polygon)
            if listvertex_hint:
                snap_vertices.extend(points)
        elif tag == "line":
            points = parse_line_element(node, matrix)
            all_vertices.extend(points)
            add_segments(points, False, outline_segments)
            if len(points) == 2:
                line_strings.append(LineString(points))
            if listvertex_hint:
                snap_vertices.extend(points)
        elif tag == "path":
            for points in parse_path_points(node.get("d") or "", matrix):
                all_vertices.extend(points)
                closed = len(points) >= 3 and math.dist(points[0], points[-1]) <= POINT_MERGE_TOL * 0.5
                add_segments(points, closed, outline_segments)
                if len(points) >= 2:
                    line_strings.append(LineString(points))
                if closed:
                    polygon = polygon_from_points(points)
                    if polygon is not None:
                        candidate_polygons.append(polygon)
                if listvertex_hint:
                    snap_vertices.extend(points)
        for child in list(node):
            walk(child, matrix)

    walk(root, np.eye(3))
    all_vertices = unique_points(all_vertices, tol=POINT_MERGE_TOL)
    snap_vertices = unique_points(snap_vertices, tol=POINT_MERGE_TOL)
    if not all_vertices:
        raise ValueError("No supported SVG geometry found. Supported tags: path, polygon, polyline, line.")
    return SvgGeometry(
        path=svg_path,
        root=root,
        tree=tree,
        view_box=view_box,
        candidate_polygons=candidate_polygons,
        line_strings=line_strings,
        all_vertices=all_vertices,
        snap_vertices=snap_vertices,
        outline_segments=outline_segments,
    )


def boundary_candidate_score(geometry: SvgGeometry, polygon: Polygon) -> float:
    cleaned = clean_polygon(polygon)
    if cleaned is None:
        return float("-inf")
    area = float(cleaned.area)
    if area <= MIN_POLYGON_AREA:
        return float("-inf")

    inside_vertices = 0
    for x, y in geometry.all_vertices:
        pt = Point(x, y)
        if cleaned.covers(pt):
            inside_vertices += 1
    vertex_ratio = inside_vertices / max(len(geometry.all_vertices), 1)

    total_line_length = 0.0
    if geometry.line_strings:
        for line in geometry.line_strings:
            try:
                total_line_length += float(line.intersection(cleaned).length)
            except Exception:
                continue
    line_density = total_line_length / max(area, 1e-6)

    bounds_area = max(
        (cleaned.bounds[2] - cleaned.bounds[0]) * (cleaned.bounds[3] - cleaned.bounds[1]),
        1e-6,
    )
    compact_fill = area / bounds_area

    return vertex_ratio * 8000.0 + line_density * 4000.0 + compact_fill * 500.0 + math.sqrt(area)


def find_boundary(geometry: SvgGeometry) -> Polygon:
    candidates: list[Polygon] = []
    if geometry.candidate_polygons:
        candidates.extend([polygon for polygon in geometry.candidate_polygons if polygon.area > MIN_POLYGON_AREA])
        try:
            merged = unary_union(candidates)
            candidates.extend(flatten_polygons(merged))
        except Exception:
            pass
    if geometry.outline_segments:
        linework = [LineString([a, b]) for a, b in geometry.outline_segments if math.dist(a, b) > 1e-9]
        try:
            polygonized = list(polygonize(unary_union(linework)))
            candidates.extend(flatten_polygons(unary_union(polygonized)))
            candidates.extend([clean_polygon(poly) for poly in polygonized if clean_polygon(poly) is not None])
        except Exception:
            pass
    if geometry.all_vertices:
        try:
            cloud = MultiPoint(geometry.all_vertices)
            for ratio in (0.005, 0.01, 0.02, 0.05, 0.1, 0.2):
                hull = concave_hull(cloud, ratio=ratio, allow_holes=False)
                candidates.extend(flatten_polygons(hull))
        except Exception:
            pass

    valid_candidates = [polygon for polygon in candidates if polygon is not None and polygon.area > MIN_POLYGON_AREA]
    if not valid_candidates:
        raise ValueError("Could not infer a valid boundary polygon from the SVG.")

    best_candidate = max(valid_candidates, key=lambda polygon: boundary_candidate_score(geometry, polygon))
    boundary = clean_polygon(best_candidate)
    if boundary is None:
        raise ValueError("Largest boundary candidate is invalid.")
    return boundary


def infer_map_polygons(geometry: SvgGeometry, boundary: Polygon) -> list[Polygon]:
    polygons: list[Polygon] = []
    for polygon in geometry.candidate_polygons:
        cleaned = clean_polygon(polygon.intersection(boundary))
        if cleaned is not None:
            polygons.append(cleaned)
    if polygons:
        return polygons
    if geometry.outline_segments:
        linework = [LineString([a, b]) for a, b in geometry.outline_segments if math.dist(a, b) > 1e-9]
        try:
            for polygon in polygonize(unary_union(linework)):
                cleaned = clean_polygon(polygon.intersection(boundary))
                if cleaned is not None:
                    polygons.append(cleaned)
        except Exception:
            pass
    return polygons


def generate_seeds(boundary: Polygon, count: int, rng: random.Random) -> list[tuple[float, float]]:
    minx, miny, maxx, maxy = boundary.bounds
    points: list[tuple[float, float]] = []
    attempts = 0
    max_attempts = max(5000, count * 400)
    while len(points) < count and attempts < max_attempts:
        attempts += 1
        x = rng.uniform(minx, maxx)
        y = rng.uniform(miny, maxy)
        if boundary.contains(Point(x, y)):
            points.append((x, y))
    if len(points) < count:
        raise RuntimeError(f"Failed to generate {count} seeds inside the inferred boundary.")
    return points


def voronoi_finite_polygons_2d(voronoi: Voronoi, radius: Optional[float] = None) -> tuple[list[list[int]], np.ndarray]:
    if voronoi.points.shape[1] != 2:
        raise ValueError("Voronoi input must be 2D.")
    regions: list[list[int]] = []
    vertices = voronoi.vertices.tolist()
    center = voronoi.points.mean(axis=0)
    if radius is None:
        radius = float(np.ptp(voronoi.points, axis=0).max() * 2.0)
    ridges: dict[int, list[tuple[int, int, int]]] = {}
    for (p1, p2), (v1, v2) in zip(voronoi.ridge_points, voronoi.ridge_vertices):
        ridges.setdefault(p1, []).append((p2, v1, v2))
        ridges.setdefault(p2, []).append((p1, v1, v2))
    for point_index, region_index in enumerate(voronoi.point_region):
        region = voronoi.regions[region_index]
        if region and all(vertex_index >= 0 for vertex_index in region):
            regions.append(region)
            continue
        new_region = [vertex_index for vertex_index in region if vertex_index >= 0] if region else []
        for neighbor_index, v1, v2 in ridges.get(point_index, []):
            if v1 >= 0 and v2 >= 0:
                continue
            tangent = voronoi.points[neighbor_index] - voronoi.points[point_index]
            length = np.linalg.norm(tangent)
            if length == 0:
                continue
            tangent /= length
            normal = np.array([-tangent[1], tangent[0]])
            midpoint = voronoi.points[[point_index, neighbor_index]].mean(axis=0)
            direction = np.sign(np.dot(midpoint - center, normal)) * normal
            finite_vertex = voronoi.vertices[v1 if v1 >= 0 else v2]
            far_point = finite_vertex + direction * radius
            new_region.append(len(vertices))
            vertices.append(far_point.tolist())
        if not new_region:
            continue
        region_points = np.asarray([vertices[index] for index in new_region], dtype=float)
        centroid = region_points.mean(axis=0)
        angles = np.arctan2(region_points[:, 1] - centroid[1], region_points[:, 0] - centroid[0])
        regions.append([vertex_index for _, vertex_index in sorted(zip(angles, new_region))])
    return regions, np.asarray(vertices, dtype=float)


def clip_cells(regions: list[list[int]], vertices: np.ndarray, boundary: Polygon) -> list[Polygon]:
    clipped_cells: list[Polygon] = []
    for region in regions:
        if len(region) < 3:
            continue
        try:
            polygon = Polygon(vertices[region])
        except Exception:
            continue
        clipped = clean_polygon(polygon.intersection(boundary))
        if clipped is not None and clipped.area > MIN_POLYGON_AREA:
            clipped_cells.append(clipped)
    return clipped_cells


def compute_area_stats(polygons: Iterable[Polygon], small_threshold: float, large_threshold: float) -> AreaStats:
    areas = np.asarray([float(poly.area) for poly in polygons if poly is not None and not poly.is_empty], dtype=float)
    if areas.size == 0:
        return AreaStats(0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0)
    average = float(areas.mean())
    small_limit = average * small_threshold
    large_limit = average * large_threshold
    too_small = int(np.sum(areas < small_limit))
    too_large = int(np.sum(areas > large_limit))
    return AreaStats(
        count=int(areas.size),
        average=average,
        minimum=float(areas.min()),
        maximum=float(areas.max()),
        std_area=float(areas.std()),
        outlier_count=too_small + too_large,
        too_small_count=too_small,
        too_large_count=too_large,
    )


def map_score(
    polygons: list[Polygon],
    small_threshold: float,
    large_threshold: float,
    movement_penalty: float = 0.0,
    w1: float = 1.0,
    w2: float = 25.0,
    w3: float = 40.0,
    w4: float = 0.5,
) -> float:
    stats = compute_area_stats(polygons, small_threshold, large_threshold)
    if stats.count == 0:
        return float("inf")
    small_limit = stats.average * small_threshold
    areas = [float(poly.area) for poly in polygons]
    extreme_small_penalty = sum(max(0.0, small_limit - area) for area in areas)
    return (
        w1 * stats.std_area
        + w2 * stats.outlier_count
        + w3 * extreme_small_penalty
        + w4 * movement_penalty
    )


def build_voronoi(
    boundary: Polygon,
    target_count: int,
    min_count: int,
    max_count: int,
    iterations: int,
    small_threshold: float,
    large_threshold: float,
    log: Callable[[str], None],
) -> tuple[list[Polygon], dict[str, Any]]:
    rng = random.Random()
    best_cells: list[Polygon] = []
    best_score = float("inf")
    best_seed_points: list[tuple[float, float]] = []
    best_stats = AreaStats(0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0)
    for iteration in range(iterations):
        seeds = generate_seeds(boundary, target_count, rng)
        voronoi = Voronoi(np.asarray(seeds, dtype=float))
        regions, vertices = voronoi_finite_polygons_2d(voronoi)
        cells = clip_cells(regions, vertices, boundary)
        stats = compute_area_stats(cells, small_threshold, large_threshold)
        score = map_score(cells, small_threshold, large_threshold)
        if stats.count < min_count:
            score += (min_count - stats.count) * 500.0
        if stats.count > max_count:
            score += (stats.count - max_count) * 500.0
        if score < best_score:
            best_cells = cells
            best_score = score
            best_seed_points = seeds
            best_stats = stats
            log(
                f"Voronoi iter {iteration + 1}/{iterations}: cells={stats.count}, "
                f"avg={stats.average:.3f}, std={stats.std_area:.3f}, outliers={stats.outlier_count}, score={score:.3f}"
            )
        if min_count <= stats.count <= max_count and stats.outlier_count == 0:
            break
    if not best_cells:
        raise RuntimeError("Voronoi generation failed for all iterations.")
    return best_cells, {
        "seed_points": best_seed_points,
        "stats": best_stats,
        "score": best_score,
    }


def score_snapped_polygon(
    polygon: Polygon,
    target_area: float,
    small_threshold: float,
    large_threshold: float,
    movement_penalty: float,
) -> float:
    area = float(polygon.area)
    small_limit = target_area * small_threshold
    large_limit = target_area * large_threshold
    std_like = abs(area - target_area)
    outlier_penalty = 0.0
    if area < small_limit:
        outlier_penalty += (small_limit - area) * 8.0
    if area > large_limit:
        outlier_penalty += (area - large_limit) * 4.0
    extreme_small_penalty = max(0.0, target_area * 0.5 - area) * 25.0
    compactness_penalty = ((polygon.length ** 2) / max(area, 1e-6)) * 0.05 if polygon.length > 0 else 0.0
    return std_like * 3.0 + outlier_penalty + extreme_small_penalty + movement_penalty * 0.5 + compactness_penalty


def snap_single_polygon(
    polygon: Polygon,
    kd_tree: cKDTree,
    snap_targets: list[tuple[float, float]],
    snap_k: int,
    target_area: float,
    small_threshold: float,
    large_threshold: float,
) -> tuple[Polygon, dict[str, float]]:
    original_points = polygon_points(polygon)
    if len(original_points) < 3:
        return polygon, {"moved_vertices": 0.0, "mean_distance": 0.0, "max_distance": 0.0}

    max_k = min(max(1, snap_k), len(snap_targets))
    try:
        distances, indices = kd_tree.query(np.asarray(original_points, dtype=float), k=max_k)
    except Exception as exc:
        raise RuntimeError(f"KDTree query failed: {exc}") from exc

    if max_k == 1:
        distances = distances[:, None]
        indices = indices[:, None]

    def evaluate(points: list[tuple[float, float]]) -> tuple[float, Optional[Polygon]]:
        candidate = polygon_with_points(points)
        if candidate is None:
            return float("inf"), None
        if not candidate.is_valid or candidate.area <= 0:
            return float("inf"), None
        movement = sum(math.dist(original_points[i], points[i]) for i in range(len(points)))
        return score_snapped_polygon(candidate, target_area, small_threshold, large_threshold, movement), candidate

    best_points = original_points[:]
    best_score, best_polygon = evaluate(best_points)
    if best_polygon is None:
        best_polygon = polygon
        best_score = score_snapped_polygon(best_polygon, target_area, small_threshold, large_threshold, 0.0)

    for vertex_index in range(len(original_points)):
        local_best_points = best_points[:]
        local_best_polygon = best_polygon
        local_best_score = best_score
        for candidate_index in range(max_k):
            candidate_point = snap_targets[int(indices[vertex_index, candidate_index])]
            trial_points = best_points[:]
            trial_points[vertex_index] = candidate_point
            trial_score, trial_polygon = evaluate(trial_points)
            if trial_polygon is not None and trial_score + 1e-9 < local_best_score:
                local_best_points = trial_points
                local_best_polygon = trial_polygon
                local_best_score = trial_score
        best_points = local_best_points
        best_polygon = local_best_polygon
        best_score = local_best_score

    snap_distances = [math.dist(original_points[i], best_points[i]) for i in range(len(original_points))]
    moved_vertices = sum(1 for distance in snap_distances if distance > 1e-6)
    return best_polygon, {
        "moved_vertices": float(moved_vertices),
        "mean_distance": float(np.mean(snap_distances)) if snap_distances else 0.0,
        "max_distance": float(np.max(snap_distances)) if snap_distances else 0.0,
    }


def snap_vertices(
    polygons: list[Polygon],
    snap_targets: list[tuple[float, float]],
    snap_k: int,
    small_threshold: float,
    large_threshold: float,
    log: Callable[[str], None],
) -> tuple[list[Polygon], dict[str, Any]]:
    if len(snap_targets) < 3:
        raise ValueError("Not enough snap vertices found in the SVG.")
    try:
        kd_tree = cKDTree(np.asarray(snap_targets, dtype=float))
    except Exception as exc:
        raise RuntimeError(f"Failed to build KDTree: {exc}") from exc

    stats_before = compute_area_stats(polygons, small_threshold, large_threshold)
    target_area = stats_before.average
    snapped_polygons: list[Polygon] = []
    total_moved = 0
    mean_distances: list[float] = []
    max_distance = 0.0
    for index, polygon in enumerate(polygons):
        snapped, meta = snap_single_polygon(
            polygon,
            kd_tree,
            snap_targets,
            snap_k,
            target_area,
            small_threshold,
            large_threshold,
        )
        snapped_polygons.append(snapped)
        total_moved += int(meta["moved_vertices"])
        mean_distances.append(float(meta["mean_distance"]))
        max_distance = max(max_distance, float(meta["max_distance"]))
        if (index + 1) % 10 == 0 or index == len(polygons) - 1:
            log(f"Snapped {index + 1}/{len(polygons)} polygons")
    stats_after = compute_area_stats(snapped_polygons, small_threshold, large_threshold)
    return snapped_polygons, {
        "before_stats": stats_before.__dict__,
        "after_stats": stats_after.__dict__,
        "snap_vertex_count": len(snap_targets),
        "snapped_vertex_count": total_moved,
        "mean_snap_distance": float(np.mean(mean_distances)) if mean_distances else 0.0,
        "max_snap_distance": max_distance,
    }


def rebalance_cells(
    polygons: list[Polygon],
    snap_targets: list[tuple[float, float]],
    snap_k: int,
    small_threshold: float,
    large_threshold: float,
    log: Callable[[str], None],
) -> tuple[list[Polygon], dict[str, Any]]:
    if len(snap_targets) < 3:
        raise ValueError("Not enough snap vertices to rebalance against.")
    current = [clean_polygon(poly) for poly in polygons]
    current = [poly for poly in current if poly is not None]
    if not current:
        raise ValueError("No polygons available for rebalance.")

    kd_tree = cKDTree(np.asarray(snap_targets, dtype=float))
    current_score = map_score(current, small_threshold, large_threshold)
    pass_count = 3
    total_improvements = 0
    total_moves = 0
    mean_distances: list[float] = []
    max_distance = 0.0

    for pass_index in range(pass_count):
        stats = compute_area_stats(current, small_threshold, large_threshold)
        if stats.count == 0:
            break
        low = stats.average * small_threshold
        high = stats.average * large_threshold
        bad_indices = [i for i, polygon in enumerate(current) if polygon.area < low or polygon.area > high]
        if not bad_indices:
            log(f"Rebalance pass {pass_index + 1}: no outlier polygons remain.")
            break
        log(f"Rebalance pass {pass_index + 1}: evaluating {len(bad_indices)} outlier polygons")
        improved_in_pass = 0
        for polygon_index in bad_indices:
            polygon = current[polygon_index]
            target_area = stats.average
            original_points = polygon_points(polygon)
            max_k = min(max(1, snap_k), len(snap_targets))
            distances, indices = kd_tree.query(np.asarray(original_points, dtype=float), k=max_k)
            if max_k == 1:
                distances = distances[:, None]
                indices = indices[:, None]

            best_polygon = polygon
            best_points = original_points[:]
            best_local_score = current_score
            improved = False

            for vertex_index in range(len(original_points)):
                for candidate_index in range(max_k):
                    candidate_point = snap_targets[int(indices[vertex_index, candidate_index])]
                    if math.dist(candidate_point, best_points[vertex_index]) <= 1e-9:
                        continue
                    trial_points = best_points[:]
                    trial_points[vertex_index] = candidate_point
                    trial_polygon = polygon_with_points(trial_points)
                    if trial_polygon is None or not trial_polygon.is_valid or trial_polygon.area <= 0:
                        continue
                    trial_polygons = current[:]
                    trial_polygons[polygon_index] = trial_polygon
                    movement_penalty = math.dist(original_points[vertex_index], candidate_point)
                    trial_score = map_score(
                        trial_polygons,
                        small_threshold,
                        large_threshold,
                        movement_penalty=movement_penalty,
                    )
                    trial_score += score_snapped_polygon(
                        trial_polygon,
                        target_area,
                        small_threshold,
                        large_threshold,
                        movement_penalty,
                    ) * 0.1
                    if trial_score + 1e-9 < best_local_score:
                        best_local_score = trial_score
                        best_polygon = trial_polygon
                        best_points = trial_points
                        improved = True

            if improved:
                current[polygon_index] = best_polygon
                current_score = best_local_score
                improved_in_pass += 1
                total_improvements += 1
                moved_distances = [math.dist(original_points[i], best_points[i]) for i in range(len(original_points))]
                moved_count = sum(1 for distance in moved_distances if distance > 1e-6)
                total_moves += moved_count
                if moved_distances:
                    mean_distances.append(float(np.mean(moved_distances)))
                    max_distance = max(max_distance, float(np.max(moved_distances)))
        if improved_in_pass == 0:
            log(f"Rebalance pass {pass_index + 1}: no improving moves found.")
            break

    final_stats = compute_area_stats(current, small_threshold, large_threshold)
    return current, {
        "stats": final_stats.__dict__,
        "score": current_score,
        "improved_polygons": total_improvements,
        "snapped_vertex_count": total_moves,
        "mean_snap_distance": float(np.mean(mean_distances)) if mean_distances else 0.0,
        "max_snap_distance": max_distance,
        "snap_vertex_count": len(snap_targets),
    }


def compute_view_box(boundary: Polygon, fallback: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
    minx, miny, maxx, maxy = boundary.bounds
    if maxx <= minx or maxy <= miny:
        return fallback
    pad_x = max((maxx - minx) * 0.02, 1.0)
    pad_y = max((maxy - miny) * 0.02, 1.0)
    return (minx - pad_x, miny - pad_y, (maxx - minx) + pad_x * 2.0, (maxy - miny) + pad_y * 2.0)


def export_boundary_debug_svg(debug_path: Path, geometry: SvgGeometry, boundary: Polygon) -> None:
    view_box = compute_view_box(boundary, geometry.view_box)
    minx, miny, width, height = view_box
    root = ET.Element(
        "svg",
        {
            "xmlns": "http://www.w3.org/2000/svg",
            "version": "1.1",
            "viewBox": f"{fmt_num(minx)} {fmt_num(miny)} {fmt_num(width)} {fmt_num(height)}",
        },
    )
    source_group = ET.SubElement(root, "g", {"id": "source"})
    for a, b in geometry.outline_segments:
        ET.SubElement(
            source_group,
            "line",
            {
                "x1": fmt_num(a[0]),
                "y1": fmt_num(a[1]),
                "x2": fmt_num(b[0]),
                "y2": fmt_num(b[1]),
                "stroke": "#000000",
                "stroke-width": "0.5",
                "fill": "none",
            },
        )
    boundary_group = ET.SubElement(root, "g", {"id": "boundary"})
    ET.SubElement(
        boundary_group,
        "polygon",
        {
            "points": " ".join(f"{fmt_num(x)},{fmt_num(y)}" for x, y in polygon_points(boundary)),
            "stroke": "#0066ff",
            "stroke-width": "2",
            "fill": "rgba(0,102,255,0.08)",
        },
    )
    ET.ElementTree(root).write(debug_path, encoding="utf-8", xml_declaration=True)


def export_svg(
    overlay_path: Path,
    map_only_path: Path,
    geometry: SvgGeometry,
    boundary: Polygon,
    polygons: list[Polygon],
) -> None:
    view_box = compute_view_box(boundary, geometry.view_box)
    minx, miny, width, height = view_box

    root_overlay = ET.Element(
        "svg",
        {
            "xmlns": "http://www.w3.org/2000/svg",
            "version": "1.1",
            "viewBox": f"{fmt_num(minx)} {fmt_num(miny)} {fmt_num(width)} {fmt_num(height)}",
        },
    )
    original_group = ET.SubElement(root_overlay, "g", {"id": "original-geometry"})
    for a, b in geometry.outline_segments:
        ET.SubElement(
            original_group,
            "line",
            {
                "x1": fmt_num(a[0]),
                "y1": fmt_num(a[1]),
                "x2": fmt_num(b[0]),
                "y2": fmt_num(b[1]),
                "stroke": "#000000",
                "stroke-width": "0.5",
                "fill": "none",
            },
        )
    map_group = ET.SubElement(root_overlay, "g", {"id": "voronoi-map"})
    for index, polygon in enumerate(polygons):
        ET.SubElement(
            map_group,
            "polygon",
            {
                "id": f"cell-{index}",
                "points": " ".join(f"{fmt_num(x)},{fmt_num(y)}" for x, y in polygon_points(polygon)),
                "stroke": "#ff0000",
                "stroke-width": "2",
                "fill": "none",
            },
        )

    root_map_only = ET.Element(
        "svg",
        {
            "xmlns": "http://www.w3.org/2000/svg",
            "version": "1.1",
            "viewBox": f"{fmt_num(minx)} {fmt_num(miny)} {fmt_num(width)} {fmt_num(height)}",
        },
    )
    map_only_group = ET.SubElement(root_map_only, "g", {"id": "voronoi-map-only"})
    for index, polygon in enumerate(polygons):
        ET.SubElement(
            map_only_group,
            "polygon",
            {
                "id": f"cell-{index}",
                "points": " ".join(f"{fmt_num(x)},{fmt_num(y)}" for x, y in polygon_points(polygon)),
                "stroke": "#ff0000",
                "stroke-width": "2",
                "fill": "none",
            },
        )

    ET.ElementTree(root_overlay).write(overlay_path, encoding="utf-8", xml_declaration=True)
    ET.ElementTree(root_map_only).write(map_only_path, encoding="utf-8", xml_declaration=True)


def export_report(
    json_path: Path,
    txt_path: Path,
    input_svg: Path,
    polygons: list[Polygon],
    stats: AreaStats,
    snap_vertex_count: int,
    extra: dict[str, Any],
) -> None:
    payload = {
        "input_svg": str(input_svg),
        "polygon_count": stats.count,
        "average_area": stats.average,
        "min_area": stats.minimum,
        "max_area": stats.maximum,
        "std_area": stats.std_area,
        "outlier_count": stats.outlier_count,
        "snap_vertex_count": snap_vertex_count,
        "polygons": [
            {
                "id": index,
                "area": float(polygon.area),
                "points": [[float(x), float(y)] for x, y in polygon_points(polygon)],
            }
            for index, polygon in enumerate(polygons)
        ],
        "meta": extra,
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "SVG Auto Voronoi Map Report",
        f"Input SVG: {input_svg}",
        "",
        f"Polygon count: {stats.count}",
        f"Average area: {stats.average:.6f}",
        f"Min area: {stats.minimum:.6f}",
        f"Max area: {stats.maximum:.6f}",
        f"Std area: {stats.std_area:.6f}",
        f"Outlier count: {stats.outlier_count}",
        f"Snap vertex count: {snap_vertex_count}",
        "",
        "Meta:",
    ]
    for key, value in extra.items():
        lines.append(f"- {key}: {value}")
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SVG Auto Voronoi Debug</title>
  <style>
    body { font-family: Consolas, monospace; margin: 0; background: #f3f4f6; color: #111827; }
    .wrap { max-width: 1280px; margin: 0 auto; padding: 24px; }
    .card { background: white; border: 1px solid #d1d5db; border-radius: 12px; padding: 16px; margin-bottom: 16px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .grid3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    label { display: block; font-size: 12px; margin-bottom: 6px; color: #374151; }
    input[type=file], input[type=text], input[type=number] { width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #9ca3af; border-radius: 8px; }
    button { border: 0; border-radius: 8px; padding: 10px 14px; background: #111827; color: white; cursor: pointer; }
    pre { white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e5e7eb; padding: 16px; border-radius: 10px; min-height: 160px; }
    iframe { width: 100%; height: 620px; border: 1px solid #d1d5db; border-radius: 10px; background: white; }
    a { color: #2563eb; text-decoration: none; }
    .error { color: #b91c1c; font-weight: 700; }
    .muted { color: #6b7280; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>SVG Auto Voronoi Debug</h1>
      <p class="muted">Voronoi chi chay trong polygon bien lon nhat suy ra tu hinh hoc SVG, khong dua vao viewBox/canvas.</p>
      <form method="post" enctype="multipart/form-data" action="{{ url_for('run_pipeline') }}">
        <div class="grid">
          <div>
            <label>SVG file</label>
            <input type="file" name="svg_file" accept=".svg" required>
          </div>
          <div>
            <label>Target cell count (100-120)</label>
            <input type="number" name="target_count" value="{{ defaults.target_count }}" min="100" max="120">
          </div>
        </div>
        <div class="grid3" style="margin-top:12px;">
          <div><label>Min cells</label><input type="number" name="min_count" value="{{ defaults.min_count }}"></div>
          <div><label>Max cells</label><input type="number" name="max_count" value="{{ defaults.max_count }}"></div>
          <div><label>Iterations</label><input type="number" name="iterations" value="{{ defaults.iterations }}"></div>
          <div><label>Snap K nearest</label><input type="number" name="snap_k" value="{{ defaults.snap_k }}"></div>
          <div><label>Small threshold</label><input type="text" name="small_threshold" value="{{ defaults.small_threshold }}"></div>
          <div><label>Large threshold</label><input type="text" name="large_threshold" value="{{ defaults.large_threshold }}"></div>
        </div>
        <div style="margin-top:16px;">
          <button type="submit">Run Debug Pipeline</button>
        </div>
      </form>
      {% if error %}
        <p class="error">{{ error }}</p>
      {% endif %}
    </div>

    {% if result %}
      <div class="card">
        <h2>Result</h2>
        <p><strong>Run ID:</strong> {{ result.run_id }}</p>
        <p><strong>Input:</strong> {{ result.input_name }}</p>
        <p><strong>Boundary area:</strong> {{ result.boundary_area }}</p>
        <p><strong>Polygon count:</strong> {{ result.stats.polygon_count }}</p>
        <p><strong>Average area:</strong> {{ result.stats.average_area }}</p>
        <p><strong>Outlier count:</strong> {{ result.stats.outlier_count }}</p>
        <p>
          <a href="{{ result.files.boundary_debug }}" target="_blank">Boundary debug SVG</a> |
          <a href="{{ result.files.overlay_svg }}" target="_blank">Overlay SVG</a> |
          <a href="{{ result.files.map_only_svg }}" target="_blank">Map-only SVG</a> |
          <a href="{{ result.files.report_json }}" target="_blank">JSON report</a> |
          <a href="{{ result.files.report_txt }}" target="_blank">TXT report</a>
        </p>
      </div>

      <div class="grid">
        <div class="card">
          <h3>Boundary Debug</h3>
          <iframe src="{{ result.files.boundary_debug }}"></iframe>
        </div>
        <div class="card">
          <h3>Overlay</h3>
          <iframe src="{{ result.files.overlay_svg }}"></iframe>
        </div>
      </div>

      <div class="card">
        <h3>Log</h3>
        <pre>{{ result.log }}</pre>
      </div>
    {% endif %}
  </div>
</body>
</html>
"""


def parse_params_from_request(req: Any) -> dict[str, Any]:
    target_count = int(req.form.get("target_count", DEFAULT_TARGET_COUNT))
    min_count = int(req.form.get("min_count", DEFAULT_MIN_COUNT))
    max_count = int(req.form.get("max_count", DEFAULT_MAX_COUNT))
    iterations = int(req.form.get("iterations", DEFAULT_ITERATIONS))
    snap_k = int(req.form.get("snap_k", DEFAULT_SNAP_K))
    small_threshold = float(req.form.get("small_threshold", DEFAULT_SMALL_THRESHOLD))
    large_threshold = float(req.form.get("large_threshold", DEFAULT_LARGE_THRESHOLD))
    if target_count <= 0 or min_count <= 0 or max_count <= 0 or iterations <= 0 or snap_k <= 0:
        raise ValueError("Counts, iterations, and snap K must be positive.")
    if not (100 <= target_count <= 120):
        raise ValueError("Target cell count must be between 100 and 120.")
    if min_count > max_count:
        raise ValueError("Min cells must be <= max cells.")
    if not (0.0 < small_threshold < 1.0):
        raise ValueError("Small threshold must be between 0 and 1.")
    if large_threshold <= 1.0:
        raise ValueError("Large threshold must be greater than 1.")
    return {
        "target_count": target_count,
        "min_count": min_count,
        "max_count": max_count,
        "iterations": iterations,
        "snap_k": snap_k,
        "small_threshold": small_threshold,
        "large_threshold": large_threshold,
    }


def run_single_svg_pipeline(svg_path: Path, params: dict[str, Any]) -> dict[str, Any]:
    log_lines: list[str] = []

    def log(message: str) -> None:
        log_lines.append(message)

    geometry = load_svg(svg_path)
    boundary = find_boundary(geometry)
    snap_targets = extract_vertices(geometry)
    log(
        f"Loaded SVG: vertices={len(geometry.all_vertices)}, "
        f"snap_targets={len(snap_targets)}, candidate_polygons={len(geometry.candidate_polygons)}"
    )
    log(f"Boundary inferred from geometry only. Area={boundary.area:.6f}, bounds={boundary.bounds}")

    voronoi_polygons, voronoi_meta = build_voronoi(
        boundary,
        params["target_count"],
        params["min_count"],
        params["max_count"],
        params["iterations"],
        params["small_threshold"],
        params["large_threshold"],
        log,
    )
    snapped_polygons, snap_meta = snap_vertices(
        voronoi_polygons,
        snap_targets,
        params["snap_k"],
        params["small_threshold"],
        params["large_threshold"],
        log,
    )
    final_polygons, rebalance_meta = rebalance_cells(
        snapped_polygons,
        snap_targets,
        params["snap_k"],
        params["small_threshold"],
        params["large_threshold"],
        log,
    )
    final_stats = compute_area_stats(final_polygons, params["small_threshold"], params["large_threshold"])

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid4().hex[:8]
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    base_name = svg_path.stem
    overlay_path = run_dir / f"{base_name}_auto_voronoi_overlay.svg"
    map_only_path = run_dir / f"{base_name}_auto_voronoi_map_only.svg"
    boundary_debug_path = run_dir / f"{base_name}_boundary_debug.svg"
    json_path = run_dir / f"{base_name}_auto_voronoi_report.json"
    txt_path = run_dir / f"{base_name}_auto_voronoi_report.txt"

    export_boundary_debug_svg(boundary_debug_path, geometry, boundary)
    export_svg(overlay_path, map_only_path, geometry, boundary, final_polygons)
    export_report(
        json_path,
        txt_path,
        svg_path,
        final_polygons,
        final_stats,
        len(snap_targets),
        {
            "params": params,
            "voronoi_score": voronoi_meta["score"],
            "seed_count": len(voronoi_meta["seed_points"]),
            **snap_meta,
            **rebalance_meta,
            "boundary_area": float(boundary.area),
            "boundary_bounds": [float(v) for v in boundary.bounds],
        },
    )

    return {
        "run_id": run_id,
        "input_name": svg_path.name,
        "boundary_area": f"{boundary.area:.6f}",
        "stats": {
            "polygon_count": final_stats.count,
            "average_area": f"{final_stats.average:.6f}",
            "outlier_count": final_stats.outlier_count,
        },
        "files": {
            "boundary_debug": url_for("serve_run_file", run_id=run_id, filename=boundary_debug_path.name),
            "overlay_svg": url_for("serve_run_file", run_id=run_id, filename=overlay_path.name),
            "map_only_svg": url_for("serve_run_file", run_id=run_id, filename=map_only_path.name),
            "report_json": url_for("serve_run_file", run_id=run_id, filename=json_path.name),
            "report_txt": url_for("serve_run_file", run_id=run_id, filename=txt_path.name),
        },
        "log": "\n".join(log_lines),
    }


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024


@app.route("/", methods=["GET"])
def index() -> str:
    defaults = {
        "target_count": DEFAULT_TARGET_COUNT,
        "min_count": DEFAULT_MIN_COUNT,
        "max_count": DEFAULT_MAX_COUNT,
        "iterations": DEFAULT_ITERATIONS,
        "snap_k": DEFAULT_SNAP_K,
        "small_threshold": DEFAULT_SMALL_THRESHOLD,
        "large_threshold": DEFAULT_LARGE_THRESHOLD,
    }
    return render_template_string(PAGE_TEMPLATE, defaults=defaults, result=None, error=None)


@app.route("/run", methods=["POST"])
def run_pipeline() -> str:
    defaults = {
        "target_count": request.form.get("target_count", DEFAULT_TARGET_COUNT),
        "min_count": request.form.get("min_count", DEFAULT_MIN_COUNT),
        "max_count": request.form.get("max_count", DEFAULT_MAX_COUNT),
        "iterations": request.form.get("iterations", DEFAULT_ITERATIONS),
        "snap_k": request.form.get("snap_k", DEFAULT_SNAP_K),
        "small_threshold": request.form.get("small_threshold", DEFAULT_SMALL_THRESHOLD),
        "large_threshold": request.form.get("large_threshold", DEFAULT_LARGE_THRESHOLD),
    }
    try:
        params = parse_params_from_request(request)
        upload = request.files.get("svg_file")
        if upload is None or not upload.filename:
            raise ValueError("Please upload one SVG file.")
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = Path(upload.filename).name
        upload_path = UPLOAD_DIR / f"{uuid4().hex}_{safe_name}"
        upload.save(upload_path)
        result = run_single_svg_pipeline(upload_path, params)
        return render_template_string(PAGE_TEMPLATE, defaults=defaults, result=result, error=None)
    except Exception as exc:
        return render_template_string(PAGE_TEMPLATE, defaults=defaults, result=None, error=f"{exc}\n{log_exception_text()}")


@app.route("/runs/<run_id>/<path:filename>", methods=["GET"])
def serve_run_file(run_id: str, filename: str) -> Any:
    return send_from_directory(RUNS_DIR / run_id, filename)


@app.route("/healthz", methods=["GET"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def main() -> None:
    FLASK_WORK_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="127.0.0.1", port=5010, debug=True)


if __name__ == "__main__":
    main()
