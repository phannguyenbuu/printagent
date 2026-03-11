"""
Install:
    pip install numpy scipy shapely

Optional for better SVG path parsing:
    pip install svgpathtools

Run:
    python svg_voronoi_snap_tool.py
"""

from __future__ import annotations

import json
import math
import random
import re
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET

from scipy.spatial import Voronoi, cKDTree
from shapely.geometry import GeometryCollection, LineString, MultiPolygon, Point, Polygon
from shapely.geometry.polygon import orient
from shapely.ops import polygonize, unary_union

try:
    from svgpathtools import parse_path as svg_parse_path
except Exception:
    svg_parse_path = None


DEFAULT_MIN_COUNT = 100
DEFAULT_MAX_COUNT = 120
DEFAULT_TARGET_COUNT = 110
DEFAULT_ITERATIONS = 40
DEFAULT_SNAP_K = 5
DEFAULT_SMALL_FACTOR = 0.75
DEFAULT_LARGE_FACTOR = 1.25
POINT_MERGE_TOL = 0.75
COLLINEAR_EPS = 1e-6
MIN_POLYGON_AREA = 1e-4


@dataclass
class SvgGeometry:
    path: Path
    view_box: tuple[float, float, float, float]
    polygons: list[Polygon] = field(default_factory=list)
    line_strings: list[LineString] = field(default_factory=list)
    all_points: list[tuple[float, float]] = field(default_factory=list)
    preferred_points: list[tuple[float, float]] = field(default_factory=list)
    outline_segments: list[tuple[tuple[float, float], tuple[float, float]]] = field(default_factory=list)


@dataclass
class PolygonRecord:
    pid: int
    polygon: Polygon
    source: str
    points: list[tuple[float, float]]
    before_area: float
    after_area: float
    snapped_vertex_count: int = 0
    mean_snap_distance: float = 0.0
    max_snap_distance: float = 0.0


@dataclass
class AreaStats:
    count: int
    average: float
    minimum: float
    maximum: float
    std_dev: float
    outlier_count: int
    too_small_count: int
    too_large_count: int


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        v = float(value)
    except Exception:
        return default
    return v if math.isfinite(v) else default


def fmt_num(value: float) -> str:
    text = f"{value:.6f}".rstrip("0").rstrip(".")
    return text or "0"


def log_exception_text() -> str:
    return traceback.format_exc(limit=8)


def unique_points(points: Iterable[tuple[float, float]], tol: float = POINT_MERGE_TOL) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    buckets: dict[tuple[int, int], list[tuple[float, float]]] = {}
    cell = max(tol, 1e-6)
    for x, y in points:
        gx = int(math.floor(x / cell))
        gy = int(math.floor(y / cell))
        found = False
        for ix in range(gx - 1, gx + 2):
            for iy in range(gy - 1, gy + 2):
                for px, py in buckets.get((ix, iy), []):
                    if (x - px) ** 2 + (y - py) ** 2 <= tol * tol:
                        found = True
                        break
                if found:
                    break
            if found:
                break
        if not found:
            pt = (float(x), float(y))
            out.append(pt)
            buckets.setdefault((gx, gy), []).append(pt)
    return out


def parse_svg_length(value: Optional[str], fallback: float) -> float:
    if not value:
        return fallback
    m = re.search(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", value)
    return safe_float(m.group(0), fallback) if m else fallback


def nearly_collinear(a: tuple[float, float], b: tuple[float, float], c: tuple[float, float], eps: float = COLLINEAR_EPS) -> bool:
    area2 = abs((b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]))
    scale = max(1.0, math.dist(a, b) + math.dist(b, c))
    return area2 <= eps * scale


def simplify_ring_points(points: list[tuple[float, float]], closed: bool = True) -> list[tuple[float, float]]:
    if not points:
        return []
    cleaned: list[tuple[float, float]] = []
    for pt in points:
        if not cleaned or math.dist(cleaned[-1], pt) > POINT_MERGE_TOL * 0.25:
            cleaned.append(pt)
    if closed and len(cleaned) > 2 and math.dist(cleaned[0], cleaned[-1]) <= POINT_MERGE_TOL * 0.25:
        cleaned.pop()
    changed = True
    while changed and len(cleaned) >= 3:
        changed = False
        result: list[tuple[float, float]] = []
        total = len(cleaned)
        for i, pt in enumerate(cleaned):
            prev_pt = cleaned[(i - 1) % total] if closed else cleaned[max(0, i - 1)]
            next_pt = cleaned[(i + 1) % total] if closed else cleaned[min(total - 1, i + 1)]
            if total > 2 and nearly_collinear(prev_pt, pt, next_pt):
                changed = True
                continue
            result.append(pt)
        if len(result) >= 3:
            cleaned = result
    return cleaned


def clean_polygon(poly: Polygon) -> Optional[Polygon]:
    if poly is None or poly.is_empty:
        return None
    out = poly if poly.is_valid else poly.buffer(0)
    if out.is_empty:
        return None
    if isinstance(out, MultiPolygon):
        out = max(out.geoms, key=lambda g: g.area, default=None)
    if out is None or out.is_empty or out.area <= MIN_POLYGON_AREA:
        return None
    pts = simplify_ring_points([(float(x), float(y)) for x, y in out.exterior.coords[:-1]], closed=True)
    if len(pts) < 3:
        return None
    out = Polygon(pts)
    out = out if out.is_valid else out.buffer(0)
    if out.is_empty:
        return None
    if isinstance(out, MultiPolygon):
        out = max(out.geoms, key=lambda g: g.area, default=None)
    if out is None or out.is_empty or out.area <= MIN_POLYGON_AREA:
        return None
    return orient(out, sign=1.0)


def polygon_from_points(points: Iterable[tuple[float, float]]) -> Optional[Polygon]:
    pts = simplify_ring_points(list(points), closed=True)
    if len(pts) < 3:
        return None
    return clean_polygon(Polygon(pts))


def flatten_polygons(geom: Any) -> list[Polygon]:
    if geom is None or geom.is_empty:
        return []
    if isinstance(geom, Polygon):
        return [orient(geom, sign=1.0)]
    if isinstance(geom, MultiPolygon):
        return [orient(g, sign=1.0) for g in geom.geoms if not g.is_empty and g.area > MIN_POLYGON_AREA]
    if isinstance(geom, GeometryCollection):
        out: list[Polygon] = []
        for sub in geom.geoms:
            out.extend(flatten_polygons(sub))
        return out
    return []


def parse_transform(transform: Optional[str]) -> np.ndarray:
    if not transform:
        return np.eye(3)
    matrix = np.eye(3)
    for name, args_text in re.findall(r"([a-zA-Z]+)\s*\(([^)]*)\)", transform):
        vals = [safe_float(v) for v in re.split(r"[,\s]+", args_text.strip()) if v.strip()]
        name = name.lower()
        op = np.eye(3)
        if name == "translate":
            tx = vals[0] if vals else 0.0
            ty = vals[1] if len(vals) > 1 else 0.0
            op = np.array([[1.0, 0.0, tx], [0.0, 1.0, ty], [0.0, 0.0, 1.0]])
        elif name == "scale":
            sx = vals[0] if vals else 1.0
            sy = vals[1] if len(vals) > 1 else sx
            op = np.array([[sx, 0.0, 0.0], [0.0, sy, 0.0], [0.0, 0.0, 1.0]])
        elif name == "rotate":
            ang = math.radians(vals[0] if vals else 0.0)
            c = math.cos(ang)
            s = math.sin(ang)
            rot = np.array([[c, -s, 0.0], [s, c, 0.0], [0.0, 0.0, 1.0]])
            if len(vals) >= 3:
                cx, cy = vals[1], vals[2]
                t1 = np.array([[1.0, 0.0, cx], [0.0, 1.0, cy], [0.0, 0.0, 1.0]])
                t2 = np.array([[1.0, 0.0, -cx], [0.0, 1.0, -cy], [0.0, 0.0, 1.0]])
                op = t1 @ rot @ t2
            else:
                op = rot
        elif name == "matrix" and len(vals) >= 6:
            a, b, c, d, e, f = vals[:6]
            op = np.array([[a, c, e], [b, d, f], [0.0, 0.0, 1.0]])
        matrix = matrix @ op
    return matrix


def apply_matrix(points: Iterable[tuple[float, float]], matrix: np.ndarray) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    for x, y in points:
        v = matrix @ np.array([x, y, 1.0], dtype=float)
        out.append((float(v[0]), float(v[1])))
    return out


def parse_points_attr(text: Optional[str]) -> list[tuple[float, float]]:
    if not text:
        return []
    tokens = re.split(r"[,\s]+", text.strip())
    vals = [safe_float(tok) for tok in tokens if tok.strip()]
    return [(vals[i], vals[i + 1]) for i in range(0, len(vals) - 1, 2)]


def parse_line_element(el: ET.Element, matrix: np.ndarray) -> list[tuple[float, float]]:
    pts = [
        (safe_float(el.get("x1")), safe_float(el.get("y1"))),
        (safe_float(el.get("x2")), safe_float(el.get("y2"))),
    ]
    return apply_matrix(pts, matrix)


def parse_poly_element(el: ET.Element, matrix: np.ndarray) -> list[tuple[float, float]]:
    return apply_matrix(parse_points_attr(el.get("points")), matrix)


def parse_rect_element(el: ET.Element, matrix: np.ndarray) -> list[tuple[float, float]]:
    x = safe_float(el.get("x"))
    y = safe_float(el.get("y"))
    w = safe_float(el.get("width"))
    h = safe_float(el.get("height"))
    return apply_matrix([(x, y), (x + w, y), (x + w, y + h), (x, y + h)], matrix)


def fallback_parse_path_points(path_d: str) -> list[list[tuple[float, float]]]:
    if not path_d:
        return []
    tokens = re.findall(r"[MmLlHhVvZz]|[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", path_d)
    if not tokens:
        return []
    paths: list[list[tuple[float, float]]] = []
    current: list[tuple[float, float]] = []
    cursor = (0.0, 0.0)
    start = (0.0, 0.0)
    idx = 0
    cmd = "M"
    while idx < len(tokens):
        token = tokens[idx]
        if re.fullmatch(r"[MmLlHhVvZz]", token):
            cmd = token
            idx += 1
            if cmd in "Zz":
                if current and current[0] != current[-1]:
                    current.append(current[0])
                if current:
                    paths.append(current)
                current = []
                cursor = start
            continue
        if cmd in "Mm":
            x = safe_float(tokens[idx])
            y = safe_float(tokens[idx + 1]) if idx + 1 < len(tokens) else 0.0
            idx += 2
            cursor = (cursor[0] + x, cursor[1] + y) if cmd == "m" else (x, y)
            start = cursor
            if current:
                paths.append(current)
            current = [cursor]
            cmd = "L" if cmd == "M" else "l"
        elif cmd in "Ll":
            x = safe_float(tokens[idx])
            y = safe_float(tokens[idx + 1]) if idx + 1 < len(tokens) else 0.0
            idx += 2
            cursor = (cursor[0] + x, cursor[1] + y) if cmd == "l" else (x, y)
            current.append(cursor)
        elif cmd in "Hh":
            x = safe_float(tokens[idx])
            idx += 1
            cursor = (cursor[0] + x, cursor[1]) if cmd == "h" else (x, cursor[1])
            current.append(cursor)
        elif cmd in "Vv":
            y = safe_float(tokens[idx])
            idx += 1
            cursor = (cursor[0], cursor[1] + y) if cmd == "v" else (cursor[0], y)
            current.append(cursor)
        else:
            break
    if current:
        paths.append(current)
    return [simplify_ring_points(path, closed=False) for path in paths if len(path) >= 2]


def parse_path_points(path_d: str, matrix: np.ndarray) -> list[list[tuple[float, float]]]:
    sampled_paths: list[list[tuple[float, float]]] = []
    if svg_parse_path is not None:
        try:
            path = svg_parse_path(path_d)
            subpath: list[tuple[float, float]] = []
            for segment in path:
                samples = max(2, int(max(segment.length(error=1e-3), 2.0) / 8.0))
                for i in range(samples + 1):
                    pt = segment.point(i / samples)
                    xy = (pt.real, pt.imag)
                    if not subpath or math.dist(subpath[-1], xy) > 1e-6:
                        subpath.append(xy)
            if subpath:
                sampled_paths = [subpath]
        except Exception:
            sampled_paths = []
    if not sampled_paths:
        sampled_paths = fallback_parse_path_points(path_d)
    return [apply_matrix(path, matrix) for path in sampled_paths if len(path) >= 2]


def element_has_listvertex_hint(el: ET.Element) -> bool:
    return any(isinstance(v, str) and "listvertex" in v.lower() for v in el.attrib.values())


def add_segments(points: list[tuple[float, float]], closed: bool, collector: list[tuple[tuple[float, float], tuple[float, float]]]) -> None:
    if len(points) < 2:
        return
    limit = len(points) if closed else len(points) - 1
    for i in range(limit):
        a = points[i]
        b = points[(i + 1) % len(points)]
        if math.dist(a, b) > 1e-9:
            collector.append((a, b))


def load_svg_geometry(svg_path: Path) -> SvgGeometry:
    tree = ET.parse(svg_path)
    root = tree.getroot()
    vb_attr = root.get("viewBox")
    width = parse_svg_length(root.get("width"), 1000.0)
    height = parse_svg_length(root.get("height"), 1000.0)
    if vb_attr:
        parts = [safe_float(v) for v in re.split(r"[,\s]+", vb_attr.strip()) if v.strip()]
        view_box = (parts[0], parts[1], parts[2], parts[3]) if len(parts) == 4 else (0.0, 0.0, width, height)
    else:
        view_box = (0.0, 0.0, width, height)

    polygons: list[Polygon] = []
    line_strings: list[LineString] = []
    all_points: list[tuple[float, float]] = []
    preferred_points: list[tuple[float, float]] = []
    outline_segments: list[tuple[tuple[float, float], tuple[float, float]]] = []

    def walk(node: ET.Element, parent_matrix: np.ndarray) -> None:
        matrix = parent_matrix @ parse_transform(node.get("transform"))
        tag = node.tag.rsplit("}", 1)[-1]
        if tag == "polygon":
            pts = parse_poly_element(node, matrix)
            all_points.extend(pts)
            add_segments(pts, True, outline_segments)
            poly = polygon_from_points(pts)
            if poly is not None:
                polygons.append(poly)
            if element_has_listvertex_hint(node):
                preferred_points.extend(pts)
        elif tag == "polyline":
            pts = parse_poly_element(node, matrix)
            all_points.extend(pts)
            add_segments(pts, False, outline_segments)
            if len(pts) >= 2:
                line_strings.append(LineString(pts))
            if len(pts) >= 3 and math.dist(pts[0], pts[-1]) <= POINT_MERGE_TOL:
                poly = polygon_from_points(pts)
                if poly is not None:
                    polygons.append(poly)
            if element_has_listvertex_hint(node):
                preferred_points.extend(pts)
        elif tag == "line":
            pts = parse_line_element(node, matrix)
            all_points.extend(pts)
            add_segments(pts, False, outline_segments)
            if len(pts) == 2:
                line_strings.append(LineString(pts))
            if element_has_listvertex_hint(node):
                preferred_points.extend(pts)
        elif tag == "rect":
            pts = parse_rect_element(node, matrix)
            all_points.extend(pts)
            add_segments(pts, True, outline_segments)
            poly = polygon_from_points(pts)
            if poly is not None:
                polygons.append(poly)
            if element_has_listvertex_hint(node):
                preferred_points.extend(pts)
        elif tag == "path":
            d_attr = node.get("d") or ""
            for pts in parse_path_points(d_attr, matrix):
                all_points.extend(pts)
                closed = len(pts) >= 3 and math.dist(pts[0], pts[-1]) <= POINT_MERGE_TOL * 0.5
                add_segments(pts, closed, outline_segments)
                if len(pts) >= 2:
                    line_strings.append(LineString(pts))
                if closed:
                    poly = polygon_from_points(pts)
                    if poly is not None:
                        polygons.append(poly)
                if element_has_listvertex_hint(node):
                    preferred_points.extend(pts)
        for child in list(node):
            walk(child, matrix)

    walk(root, np.eye(3))
    return SvgGeometry(
        path=svg_path,
        view_box=view_box,
        polygons=polygons,
        line_strings=line_strings,
        all_points=unique_points(all_points),
        preferred_points=unique_points(preferred_points),
        outline_segments=outline_segments,
    )


def build_main_boundary(geometry: SvgGeometry) -> Polygon:
    candidates: list[Polygon] = []
    if geometry.polygons:
        unioned = unary_union([p for p in geometry.polygons if p.area > MIN_POLYGON_AREA])
        candidates.extend(flatten_polygons(unioned))
        candidates.extend([p for p in geometry.polygons if p.area > MIN_POLYGON_AREA])
    if geometry.outline_segments:
        linework = [LineString([a, b]) for a, b in geometry.outline_segments if math.dist(a, b) > 1e-9]
        merged = unary_union(linework)
        candidates.extend(flatten_polygons(unary_union(list(polygonize(merged)))))
    if not candidates:
        raise ValueError(f"Cannot build main boundary polygon from {geometry.path}")
    poly = orient(max(candidates, key=lambda p: p.area).buffer(0), sign=1.0)
    if poly.is_empty or poly.area <= MIN_POLYGON_AREA:
        raise ValueError("Main boundary polygon is invalid or empty")
    return poly


def get_black_target_vertices(geometry: SvgGeometry) -> list[tuple[float, float]]:
    points = geometry.preferred_points or geometry.all_points
    points = unique_points(points, tol=POINT_MERGE_TOL)
    if len(points) < 3:
        raise ValueError("Not enough black vertices to snap")
    return points


def voronoi_finite_polygons_2d(vor: Voronoi, radius: Optional[float] = None) -> tuple[list[list[int]], np.ndarray]:
    if vor.points.shape[1] != 2:
        raise ValueError("Voronoi input must be 2D")
    new_regions: list[list[int]] = []
    new_vertices = vor.vertices.tolist()
    center = vor.points.mean(axis=0)
    if radius is None:
        radius = float(vor.points.ptp().max() * 2.0)
    all_ridges: dict[int, list[tuple[int, int, int]]] = {}
    for (p1, p2), (v1, v2) in zip(vor.ridge_points, vor.ridge_vertices):
        all_ridges.setdefault(p1, []).append((p2, v1, v2))
        all_ridges.setdefault(p2, []).append((p1, v1, v2))
    for p1, region_idx in enumerate(vor.point_region):
        region = vor.regions[region_idx]
        if all(v >= 0 for v in region):
            new_regions.append(region)
            continue
        new_region = [v for v in region if v >= 0]
        for p2, v1, v2 in all_ridges.get(p1, []):
            if v1 >= 0 and v2 >= 0:
                continue
            tangent = vor.points[p2] - vor.points[p1]
            norm = np.linalg.norm(tangent)
            if norm == 0:
                continue
            tangent /= norm
            normal = np.array([-tangent[1], tangent[0]])
            midpoint = vor.points[[p1, p2]].mean(axis=0)
            direction = np.sign(np.dot(midpoint - center, normal)) * normal
            far_point = vor.vertices[v1 if v1 >= 0 else v2] + direction * radius
            new_region.append(len(new_vertices))
            new_vertices.append(far_point.tolist())
        vs = np.asarray([new_vertices[v] for v in new_region], dtype=float)
        centroid = vs.mean(axis=0)
        angles = np.arctan2(vs[:, 1] - centroid[1], vs[:, 0] - centroid[0])
        new_regions.append([v for _, v in sorted(zip(angles, new_region))])
    return new_regions, np.asarray(new_vertices, dtype=float)


def generate_random_points_in_polygon(polygon: Polygon, count: int, rng: random.Random) -> list[tuple[float, float]]:
    minx, miny, maxx, maxy = polygon.bounds
    points: list[tuple[float, float]] = []
    attempts = 0
    max_attempts = max(5000, count * 400)
    while len(points) < count and attempts < max_attempts:
        attempts += 1
        x = rng.uniform(minx, maxx)
        y = rng.uniform(miny, maxy)
        if polygon.contains(Point(x, y)):
            points.append((x, y))
    if len(points) < count:
        raise RuntimeError(f"Failed to generate enough seeds inside polygon ({len(points)}/{count})")
    return points


def area_stats(polygons: Iterable[Polygon], small_factor: float, large_factor: float) -> AreaStats:
    areas = np.array([float(poly.area) for poly in polygons if poly is not None and not poly.is_empty], dtype=float)
    if areas.size == 0:
        return AreaStats(0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0)
    avg = float(areas.mean())
    low = avg * small_factor
    high = avg * large_factor
    too_small = int(np.sum(areas < low))
    too_large = int(np.sum(areas > high))
    return AreaStats(
        count=int(areas.size),
        average=avg,
        minimum=float(areas.min()),
        maximum=float(areas.max()),
        std_dev=float(areas.std()),
        outlier_count=too_small + too_large,
        too_small_count=too_small,
        too_large_count=too_large,
    )


def score_area_distribution(stats: AreaStats, min_count: int, max_count: int, small_factor: float) -> float:
    if stats.count == 0:
        return float("inf")
    count_penalty = 0.0
    if stats.count < min_count:
        count_penalty += (min_count - stats.count) * 500.0
    if stats.count > max_count:
        count_penalty += (stats.count - max_count) * 500.0
    tiny_threshold = stats.average * max(0.35, small_factor * 0.5)
    tiny_penalty = (tiny_threshold - stats.minimum) * 100.0 if stats.minimum < tiny_threshold else 0.0
    return count_penalty + stats.std_dev * 3.0 + stats.outlier_count * 60.0 + tiny_penalty


def build_voronoi_cells(
    boundary_polygon: Polygon,
    target_count: int,
    min_count: int,
    max_count: int,
    iterations: int,
    small_factor: float,
    large_factor: float,
    log: callable,
) -> tuple[list[Polygon], dict[str, Any]]:
    rng = random.Random()
    best_cells: list[Polygon] = []
    best_score = float("inf")
    best_stats = AreaStats(0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0)
    best_seed: list[tuple[float, float]] = []
    for iteration in range(iterations):
        seeds = generate_random_points_in_polygon(boundary_polygon, target_count, rng)
        vor = Voronoi(np.asarray(seeds, dtype=float))
        regions, vertices = voronoi_finite_polygons_2d(vor)
        cells: list[Polygon] = []
        for region in regions:
            if not region:
                continue
            clipped = clean_polygon(Polygon(vertices[region]).intersection(boundary_polygon))
            if clipped is not None and clipped.area > MIN_POLYGON_AREA:
                cells.append(clipped)
        stats = area_stats(cells, small_factor, large_factor)
        score = score_area_distribution(stats, min_count, max_count, small_factor)
        if score < best_score:
            best_cells = cells
            best_score = score
            best_stats = stats
            best_seed = seeds
            log(
                f"Voronoi iter {iteration + 1}/{iterations}: cells={stats.count}, "
                f"avg={stats.average:.2f}, std={stats.std_dev:.2f}, outliers={stats.outlier_count}, score={score:.2f}"
            )
        if min_count <= stats.count <= max_count and stats.outlier_count == 0:
            break
    if not best_cells:
        raise RuntimeError("Failed to generate Voronoi cells")
    return best_cells, {"seed_points": best_seed, "stats": best_stats, "score": best_score}


def polygons_from_map_geometry(geometry: SvgGeometry) -> list[Polygon]:
    polygons = [clean_polygon(poly) for poly in geometry.polygons]
    polygons = [poly for poly in polygons if poly is not None]
    if polygons:
        return polygons
    if geometry.outline_segments:
        linework = [LineString([a, b]) for a, b in geometry.outline_segments if math.dist(a, b) > 1e-9]
        polygons = [clean_polygon(poly) for poly in polygonize(unary_union(linework))]
        polygons = [poly for poly in polygons if poly is not None]
        if polygons:
            return polygons
    raise ValueError(f"No polygon-like geometry found in {geometry.path}")


def polygon_points(poly: Polygon) -> list[tuple[float, float]]:
    return [(float(x), float(y)) for x, y in list(poly.exterior.coords[:-1])]


def polygon_with_points(points: list[tuple[float, float]]) -> Optional[Polygon]:
    return clean_polygon(Polygon(points))


def polygon_quality_score(polygon: Polygon, target_area: float, small_factor: float, large_factor: float, movement_penalty: float) -> float:
    area = float(polygon.area)
    std_like = abs(area - target_area)
    outlier_penalty = 0.0
    if area < target_area * small_factor:
        outlier_penalty += (target_area * small_factor - area) * 8.0
    if area > target_area * large_factor:
        outlier_penalty += (area - target_area * large_factor) * 4.0
    small_penalty = 0.0
    if area < target_area * 0.5:
        small_penalty = (target_area * 0.5 - area) * 25.0
    compactness = (polygon.length * polygon.length) / max(area, 1e-6) if polygon.length > 0 else 0.0
    return std_like * 3.0 + outlier_penalty + small_penalty + movement_penalty * 0.5 + compactness * 0.05


def snap_polygon_vertices(
    polygon: Polygon,
    kd_tree: cKDTree,
    target_vertices: list[tuple[float, float]],
    snap_k: int,
    target_area: float,
    small_factor: float,
    large_factor: float,
) -> tuple[Polygon, int, float, float]:
    original_points = polygon_points(polygon)
    if len(original_points) < 3:
        return polygon, 0, 0.0, 0.0
    query = np.asarray(original_points, dtype=float)
    max_k = min(max(1, snap_k), len(target_vertices))
    distances, indices = kd_tree.query(query, k=max_k)
    if max_k == 1:
        distances = distances[:, None]
        indices = indices[:, None]

    def evaluate(points: list[tuple[float, float]]) -> tuple[float, Optional[Polygon]]:
        poly = polygon_with_points(points)
        if poly is None:
            return float("inf"), None
        movement = sum(math.dist(original_points[i], points[i]) for i in range(len(points)))
        return polygon_quality_score(poly, target_area, small_factor, large_factor, movement), poly

    best_points = [target_vertices[int(indices[i, 0])] for i in range(len(original_points))]
    best_score, best_polygon = evaluate(best_points)
    if best_polygon is None:
        best_points = original_points[:]
        best_polygon = polygon
        best_score = polygon_quality_score(best_polygon, target_area, small_factor, large_factor, 0.0)

    area_now = best_polygon.area
    need_rebalance = area_now < target_area * small_factor or area_now > target_area * large_factor
    if need_rebalance:
        for idx in range(len(original_points)):
            local_best_points = best_points
            local_best_polygon = best_polygon
            local_best_score = best_score
            for alt in range(max_k):
                candidate = target_vertices[int(indices[idx, alt])]
                if math.dist(candidate, best_points[idx]) <= 1e-9:
                    continue
                trial_points = best_points[:]
                trial_points[idx] = candidate
                trial_score, trial_polygon = evaluate(trial_points)
                if trial_polygon is not None and trial_score + 1e-9 < local_best_score:
                    local_best_points = trial_points
                    local_best_polygon = trial_polygon
                    local_best_score = trial_score
            best_points = local_best_points
            best_polygon = local_best_polygon
            best_score = local_best_score

        area_now = best_polygon.area
        if area_now < target_area * small_factor or area_now > target_area * large_factor:
            for i in range(len(original_points)):
                improved = False
                for j in range(i + 1, len(original_points)):
                    for alt_i in range(1, max_k):
                        for alt_j in range(1, max_k):
                            trial_points = best_points[:]
                            trial_points[i] = target_vertices[int(indices[i, alt_i])]
                            trial_points[j] = target_vertices[int(indices[j, alt_j])]
                            trial_score, trial_polygon = evaluate(trial_points)
                            if trial_polygon is not None and trial_score + 1e-9 < best_score:
                                best_points = trial_points
                                best_polygon = trial_polygon
                                best_score = trial_score
                                improved = True
                                break
                        if improved:
                            break
                    if improved:
                        break
                if improved:
                    break

    snap_distances = [math.dist(original_points[i], best_points[i]) for i in range(len(original_points))]
    moved_count = sum(1 for d in snap_distances if d > 1e-6)
    return (
        best_polygon,
        moved_count,
        float(np.mean(snap_distances)) if snap_distances else 0.0,
        float(np.max(snap_distances)) if snap_distances else 0.0,
    )


def rebalance_map_polygons(
    polygons: list[Polygon],
    target_vertices: list[tuple[float, float]],
    snap_k: int,
    small_factor: float,
    large_factor: float,
    log: callable,
) -> tuple[list[PolygonRecord], dict[str, Any]]:
    if not polygons:
        raise ValueError("No polygons available for snap / rebalance")
    kd_tree = cKDTree(np.asarray(target_vertices, dtype=float))
    before_stats = area_stats(polygons, small_factor, large_factor)
    target_area = before_stats.average
    records: list[PolygonRecord] = []
    snapped_polys: list[Polygon] = []
    total_snapped_vertices = 0
    mean_samples: list[float] = []
    max_snap_distance = 0.0
    for idx, poly in enumerate(polygons):
        snapped, moved_count, mean_snap, max_snap = snap_polygon_vertices(
            poly, kd_tree, target_vertices, snap_k, target_area, small_factor, large_factor
        )
        records.append(
            PolygonRecord(
                pid=idx,
                polygon=snapped,
                source="snap",
                points=polygon_points(snapped),
                before_area=float(poly.area),
                after_area=float(snapped.area),
                snapped_vertex_count=moved_count,
                mean_snap_distance=mean_snap,
                max_snap_distance=max_snap,
            )
        )
        snapped_polys.append(snapped)
        total_snapped_vertices += moved_count
        mean_samples.append(mean_snap)
        max_snap_distance = max(max_snap_distance, max_snap)
    after_stats = area_stats(snapped_polys, small_factor, large_factor)
    log(
        f"Snap complete: polygons={after_stats.count}, avg={after_stats.average:.2f}, "
        f"std={after_stats.std_dev:.2f}, outliers={after_stats.outlier_count}, snapped_vertices={total_snapped_vertices}"
    )
    return records, {
        "before_stats": before_stats,
        "after_stats": after_stats,
        "snapped_vertex_count": total_snapped_vertices,
        "mean_snap_distance": float(np.mean(mean_samples)) if mean_samples else 0.0,
        "max_snap_distance": max_snap_distance,
        "black_vertex_count": len(target_vertices),
    }


def records_from_polygons(polygons: list[Polygon], source: str) -> list[PolygonRecord]:
    records: list[PolygonRecord] = []
    for idx, poly in enumerate(polygons):
        cleaned = clean_polygon(poly)
        if cleaned is None:
            continue
        records.append(
            PolygonRecord(
                pid=idx,
                polygon=cleaned,
                source=source,
                points=polygon_points(cleaned),
                before_area=float(cleaned.area),
                after_area=float(cleaned.area),
            )
        )
    return records


def compute_view_box(boundary: Polygon, fallback: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
    if boundary and not boundary.is_empty:
        minx, miny, maxx, maxy = boundary.bounds
        pad_x = max((maxx - minx) * 0.02, 1.0)
        pad_y = max((maxy - miny) * 0.02, 1.0)
        return (minx - pad_x, miny - pad_y, (maxx - minx) + pad_x * 2.0, (maxy - miny) + pad_y * 2.0)
    return fallback


def write_svg_outputs(
    overlay_path: Path,
    map_only_path: Path,
    boundary_polygon: Polygon,
    outline_segments: list[tuple[tuple[float, float], tuple[float, float]]],
    records: list[PolygonRecord],
    view_box: tuple[float, float, float, float],
) -> None:
    minx, miny, width, height = view_box
    root_overlay = ET.Element(
        "svg",
        {"xmlns": "http://www.w3.org/2000/svg", "version": "1.1", "viewBox": f"{fmt_num(minx)} {fmt_num(miny)} {fmt_num(width)} {fmt_num(height)}"},
    )
    outline_group = ET.SubElement(root_overlay, "g", {"id": "outline"})
    if outline_segments:
        for a, b in outline_segments:
            ET.SubElement(
                outline_group,
                "line",
                {
                    "x1": fmt_num(a[0]),
                    "y1": fmt_num(a[1]),
                    "x2": fmt_num(b[0]),
                    "y2": fmt_num(b[1]),
                    "stroke": "#000000",
                    "stroke-width": "0.8",
                    "fill": "none",
                },
            )
    else:
        ET.SubElement(
            outline_group,
            "polygon",
            {
                "points": " ".join(f"{fmt_num(x)},{fmt_num(y)}" for x, y in polygon_points(boundary_polygon)),
                "stroke": "#000000",
                "stroke-width": "0.8",
                "fill": "none",
            },
        )
    map_group = ET.SubElement(root_overlay, "g", {"id": "map"})
    for record in records:
        ET.SubElement(
            map_group,
            "polygon",
            {
                "id": f"poly-{record.pid}",
                "points": " ".join(f"{fmt_num(x)},{fmt_num(y)}" for x, y in record.points),
                "stroke": "#ff0000",
                "stroke-width": "1.8",
                "fill": "none",
            },
        )

    root_map = ET.Element(
        "svg",
        {"xmlns": "http://www.w3.org/2000/svg", "version": "1.1", "viewBox": f"{fmt_num(minx)} {fmt_num(miny)} {fmt_num(width)} {fmt_num(height)}"},
    )
    map_only_group = ET.SubElement(root_map, "g", {"id": "map-only"})
    for record in records:
        ET.SubElement(
            map_only_group,
            "polygon",
            {
                "id": f"poly-{record.pid}",
                "points": " ".join(f"{fmt_num(x)},{fmt_num(y)}" for x, y in record.points),
                "stroke": "#ff0000",
                "stroke-width": "1.8",
                "fill": "none",
            },
        )

    ET.ElementTree(root_overlay).write(overlay_path, encoding="utf-8", xml_declaration=True)
    ET.ElementTree(root_map).write(map_only_path, encoding="utf-8", xml_declaration=True)


def write_json_report(
    json_path: Path,
    outline_file: Optional[Path],
    map_file: Optional[Path],
    overlay_file: Path,
    map_only_file: Path,
    stats: AreaStats,
    black_vertex_count: int,
    records: list[PolygonRecord],
) -> None:
    payload = {
        "input_files": {"outline_svg": str(outline_file) if outline_file else "", "map_svg": str(map_file) if map_file else ""},
        "output_files": {
            "overlay_svg": str(overlay_file),
            "map_only_svg": str(map_only_file),
            "json": str(json_path),
        },
        "polygon_count": stats.count,
        "average_area": stats.average,
        "min_area": stats.minimum,
        "max_area": stats.maximum,
        "std_area": stats.std_dev,
        "outlier_count": stats.outlier_count,
        "black_vertex_count": black_vertex_count,
        "polygons": [
            {
                "id": record.pid,
                "area": float(record.polygon.area),
                "points": [[float(x), float(y)] for x, y in record.points],
                "snapped_vertex_count": record.snapped_vertex_count,
                "mean_snap_distance": record.mean_snap_distance,
                "max_snap_distance": record.max_snap_distance,
                "before_area": record.before_area,
                "after_area": record.after_area,
            }
            for record in records
        ],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text_report(
    txt_path: Path,
    outline_file: Optional[Path],
    map_file: Optional[Path],
    stats_before: Optional[AreaStats],
    stats_after: AreaStats,
    black_vertex_count: int,
    snapped_vertex_count: int,
    mean_snap_distance: float,
    max_snap_distance: float,
    params: dict[str, Any],
) -> None:
    lines = [
        "SVG Voronoi / Snap Report",
        "=" * 40,
        f"Outline SVG: {outline_file or ''}",
        f"Map SVG: {map_file or ''}",
        "",
        f"Black vertex count: {black_vertex_count}",
        f"Polygon count: {stats_after.count}",
        "",
        "Parameters:",
        f"  min polygon count: {params.get('min_count')}",
        f"  max polygon count: {params.get('max_count')}",
        f"  target count: {params.get('target_count')}",
        f"  iterations: {params.get('iterations')}",
        f"  snap K nearest: {params.get('snap_k')}",
        f"  small threshold factor: {params.get('small_factor')}",
        f"  large threshold factor: {params.get('large_factor')}",
        "",
    ]
    if stats_before is not None:
        lines.extend(
            [
                "Area stats before snap:",
                f"  average: {stats_before.average:.4f}",
                f"  min: {stats_before.minimum:.4f}",
                f"  max: {stats_before.maximum:.4f}",
                f"  std: {stats_before.std_dev:.4f}",
                f"  too small: {stats_before.too_small_count}",
                f"  too large: {stats_before.too_large_count}",
                "",
            ]
        )
    lines.extend(
        [
            "Area stats after output:",
            f"  average: {stats_after.average:.4f}",
            f"  min: {stats_after.minimum:.4f}",
            f"  max: {stats_after.maximum:.4f}",
            f"  std: {stats_after.std_dev:.4f}",
            f"  too small: {stats_after.too_small_count}",
            f"  too large: {stats_after.too_large_count}",
            f"  outliers total: {stats_after.outlier_count}",
            "",
            f"Snapped vertices: {snapped_vertex_count}",
            f"Average snap distance: {mean_snap_distance:.4f}",
            f"Max snap distance: {max_snap_distance:.4f}",
        ]
    )
    txt_path.write_text("\n".join(lines), encoding="utf-8")


class VoronoiSnapApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SVG Voronoi Snap Tool")
        self.root.geometry("980x760")

        self.outline_path_var = tk.StringVar()
        self.map_path_var = tk.StringVar()
        self.export_base_var = tk.StringVar()
        self.min_count_var = tk.StringVar(value=str(DEFAULT_MIN_COUNT))
        self.max_count_var = tk.StringVar(value=str(DEFAULT_MAX_COUNT))
        self.target_count_var = tk.StringVar(value=str(DEFAULT_TARGET_COUNT))
        self.iterations_var = tk.StringVar(value=str(DEFAULT_ITERATIONS))
        self.snap_k_var = tk.StringVar(value=str(DEFAULT_SNAP_K))
        self.small_factor_var = tk.StringVar(value=str(DEFAULT_SMALL_FACTOR))
        self.large_factor_var = tk.StringVar(value=str(DEFAULT_LARGE_FACTOR))

        self.outline_geometry: Optional[SvgGeometry] = None
        self.map_geometry: Optional[SvgGeometry] = None
        self.boundary_polygon: Optional[Polygon] = None
        self.current_records: list[PolygonRecord] = []
        self.last_before_stats: Optional[AreaStats] = None
        self.last_after_stats: Optional[AreaStats] = None
        self.last_snap_meta: dict[str, Any] = {}

        self._build_ui()

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        file_frame = ttk.LabelFrame(main, text="Files", padding=8)
        file_frame.pack(fill="x")
        self._add_file_row(file_frame, 0, "Outline SVG", self.outline_path_var, self.choose_outline_file)
        self._add_file_row(file_frame, 1, "Map SVG", self.map_path_var, self.choose_map_file)
        self._add_file_row(file_frame, 2, "Export Base", self.export_base_var, self.choose_export_base)

        params = ttk.LabelFrame(main, text="Parameters", padding=8)
        params.pack(fill="x", pady=(10, 0))
        param_items = [
            ("Min polygon count", self.min_count_var),
            ("Max polygon count", self.max_count_var),
            ("Target count", self.target_count_var),
            ("Iteration count", self.iterations_var),
            ("Snap K nearest", self.snap_k_var),
            ("Small threshold factor", self.small_factor_var),
            ("Large threshold factor", self.large_factor_var),
        ]
        for idx, (label, var) in enumerate(param_items):
            row = idx // 2
            col = (idx % 2) * 2
            ttk.Label(params, text=label).grid(row=row, column=col, sticky="w", padx=(0, 6), pady=4)
            ttk.Entry(params, textvariable=var, width=16).grid(row=row, column=col + 1, sticky="we", pady=4)

        actions = ttk.Frame(main)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Run Voronoi", command=self.run_voronoi).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Run Snap / Rebalance", command=self.run_snap).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Run All", command=self.run_all).pack(side="left")

        log_frame = ttk.LabelFrame(main, text="Status / Progress", padding=8)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.log_text = tk.Text(log_frame, wrap="word", height=28)
        self.log_text.pack(fill="both", expand=True)

    def _add_file_row(self, parent: ttk.LabelFrame, row: int, label: str, var: tk.StringVar, command: callable) -> None:
        ttk.Label(parent, text=label, width=12).grid(row=row, column=0, sticky="w", padx=(0, 6), pady=4)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="we", padx=(0, 6), pady=4)
        ttk.Button(parent, text="Browse...", command=command).grid(row=row, column=2, sticky="e", pady=4)
        parent.columnconfigure(1, weight=1)

    def log(self, message: str) -> None:
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.root.update_idletasks()

    def choose_outline_file(self) -> None:
        path = filedialog.askopenfilename(title="Select outline SVG", filetypes=[("SVG files", "*.svg")])
        if path:
            self.outline_path_var.set(path)

    def choose_map_file(self) -> None:
        path = filedialog.askopenfilename(title="Select map SVG", filetypes=[("SVG files", "*.svg")])
        if path:
            self.map_path_var.set(path)

    def choose_export_base(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Select export base file",
            defaultextension=".svg",
            filetypes=[("SVG files", "*.svg"), ("All files", "*.*")],
        )
        if path:
            self.export_base_var.set(path)

    def parse_params(self) -> dict[str, Any]:
        min_count = int(self.min_count_var.get().strip() or DEFAULT_MIN_COUNT)
        max_count = int(self.max_count_var.get().strip() or DEFAULT_MAX_COUNT)
        target_count = int(self.target_count_var.get().strip() or DEFAULT_TARGET_COUNT)
        iterations = int(self.iterations_var.get().strip() or DEFAULT_ITERATIONS)
        snap_k = int(self.snap_k_var.get().strip() or DEFAULT_SNAP_K)
        small_factor = float(self.small_factor_var.get().strip() or DEFAULT_SMALL_FACTOR)
        large_factor = float(self.large_factor_var.get().strip() or DEFAULT_LARGE_FACTOR)
        if min_count <= 0 or max_count <= 0 or target_count <= 0 or iterations <= 0:
            raise ValueError("Counts and iterations must be positive")
        if min_count > max_count:
            raise ValueError("Min polygon count must be <= max polygon count")
        if not (0.0 < small_factor < 1.0):
            raise ValueError("Small threshold factor must be between 0 and 1")
        if large_factor <= 1.0:
            raise ValueError("Large threshold factor must be > 1")
        return {
            "min_count": min_count,
            "max_count": max_count,
            "target_count": target_count,
            "iterations": iterations,
            "snap_k": snap_k,
            "small_factor": small_factor,
            "large_factor": large_factor,
        }

    def ensure_export_paths(self) -> tuple[Path, Path, Path, Path]:
        export_base = self.export_base_var.get().strip()
        if not export_base:
            raise ValueError("Please select an export base file")
        base_path = Path(export_base)
        out_dir = base_path.parent if base_path.parent else Path.cwd()
        stem = base_path.stem or "svg_voronoi_snap"
        out_dir.mkdir(parents=True, exist_ok=True)
        return (
            out_dir / f"{stem}_overlay.svg",
            out_dir / f"{stem}_map_only.svg",
            out_dir / f"{stem}_polygons.json",
            out_dir / f"{stem}_report.txt",
        )

    def load_outline(self) -> tuple[SvgGeometry, Polygon, list[tuple[float, float]]]:
        outline_path = self.outline_path_var.get().strip()
        if not outline_path:
            raise ValueError("Please choose an outline SVG")
        path = Path(outline_path)
        if self.outline_geometry is None or path != self.outline_geometry.path:
            self.log(f"Loading outline SVG: {outline_path}")
            self.outline_geometry = load_svg_geometry(path)
            self.boundary_polygon = None
        if self.boundary_polygon is None:
            self.boundary_polygon = build_main_boundary(self.outline_geometry)
        black_vertices = get_black_target_vertices(self.outline_geometry)
        self.log(
            f"Outline loaded: polygons={len(self.outline_geometry.polygons)}, "
            f"segments={len(self.outline_geometry.outline_segments)}, black_vertices={len(black_vertices)}"
        )
        return self.outline_geometry, self.boundary_polygon, black_vertices

    def load_map(self) -> Optional[SvgGeometry]:
        map_path = self.map_path_var.get().strip()
        if not map_path:
            return None
        path = Path(map_path)
        if self.map_geometry is None or path != self.map_geometry.path:
            self.log(f"Loading map SVG: {map_path}")
            self.map_geometry = load_svg_geometry(path)
        self.log(
            f"Map loaded: polygons={len(self.map_geometry.polygons)}, "
            f"segments={len(self.map_geometry.outline_segments)}"
        )
        return self.map_geometry

    def export_all(
        self,
        outline_geometry: SvgGeometry,
        boundary_polygon: Polygon,
        records: list[PolygonRecord],
        black_vertices: list[tuple[float, float]],
        params: dict[str, Any],
    ) -> None:
        overlay_svg, map_only_svg, json_file, txt_file = self.ensure_export_paths()
        view_box = compute_view_box(boundary_polygon, outline_geometry.view_box)
        write_svg_outputs(overlay_svg, map_only_svg, boundary_polygon, outline_geometry.outline_segments, records, view_box)
        stats_after = area_stats([record.polygon for record in records], params["small_factor"], params["large_factor"])
        self.last_after_stats = stats_after
        write_json_report(
            json_file,
            outline_geometry.path,
            self.map_geometry.path if self.map_geometry else None,
            overlay_svg,
            map_only_svg,
            stats_after,
            len(black_vertices),
            records,
        )
        write_text_report(
            txt_file,
            outline_geometry.path,
            self.map_geometry.path if self.map_geometry else None,
            self.last_before_stats,
            stats_after,
            len(black_vertices),
            int(self.last_snap_meta.get("snapped_vertex_count", 0)),
            float(self.last_snap_meta.get("mean_snap_distance", 0.0)),
            float(self.last_snap_meta.get("max_snap_distance", 0.0)),
            params,
        )
        self.log(f"Exported overlay SVG: {overlay_svg}")
        self.log(f"Exported map-only SVG: {map_only_svg}")
        self.log(f"Exported JSON: {json_file}")
        self.log(f"Exported TXT report: {txt_file}")

    def run_voronoi(self) -> None:
        try:
            params = self.parse_params()
            outline_geometry, boundary_polygon, black_vertices = self.load_outline()
            self.log("Running Voronoi pipeline...")
            cells, meta = build_voronoi_cells(
                boundary_polygon,
                params["target_count"],
                params["min_count"],
                params["max_count"],
                params["iterations"],
                params["small_factor"],
                params["large_factor"],
                self.log,
            )
            self.current_records = records_from_polygons(cells, source="voronoi")
            self.last_before_stats = None
            self.last_after_stats = meta["stats"]
            self.last_snap_meta = {"snapped_vertex_count": 0, "mean_snap_distance": 0.0, "max_snap_distance": 0.0}
            self.export_all(outline_geometry, boundary_polygon, self.current_records, black_vertices, params)
            messagebox.showinfo("Done", "Voronoi export completed.")
        except Exception as exc:
            self.log(f"ERROR: {exc}")
            self.log(log_exception_text())
            messagebox.showerror("Error", str(exc))

    def run_snap(self) -> None:
        try:
            params = self.parse_params()
            outline_geometry, boundary_polygon, black_vertices = self.load_outline()
            map_geometry = self.load_map()
            if map_geometry is not None:
                source_polygons = polygons_from_map_geometry(map_geometry)
                self.last_before_stats = area_stats(source_polygons, params["small_factor"], params["large_factor"])
            elif self.current_records:
                source_polygons = [record.polygon for record in self.current_records]
                self.last_before_stats = area_stats(source_polygons, params["small_factor"], params["large_factor"])
            else:
                raise ValueError("Please choose a map SVG or run Voronoi first")
            self.log("Running Snap / Rebalance pipeline...")
            records, meta = rebalance_map_polygons(
                source_polygons,
                black_vertices,
                params["snap_k"],
                params["small_factor"],
                params["large_factor"],
                self.log,
            )
            self.current_records = records
            self.last_snap_meta = meta
            self.last_after_stats = meta["after_stats"]
            self.export_all(outline_geometry, boundary_polygon, records, black_vertices, params)
            messagebox.showinfo("Done", "Snap / Rebalance export completed.")
        except Exception as exc:
            self.log(f"ERROR: {exc}")
            self.log(log_exception_text())
            messagebox.showerror("Error", str(exc))

    def run_all(self) -> None:
        try:
            params = self.parse_params()
            outline_geometry, boundary_polygon, black_vertices = self.load_outline()
            map_geometry = self.load_map()
            if map_geometry is None:
                self.log("Map SVG not selected; generating Voronoi first.")
                cells, meta = build_voronoi_cells(
                    boundary_polygon,
                    params["target_count"],
                    params["min_count"],
                    params["max_count"],
                    params["iterations"],
                    params["small_factor"],
                    params["large_factor"],
                    self.log,
                )
                source_polygons = cells
                self.last_before_stats = meta["stats"]
            else:
                source_polygons = polygons_from_map_geometry(map_geometry)
                self.last_before_stats = area_stats(source_polygons, params["small_factor"], params["large_factor"])
            self.log("Running final Snap / Rebalance...")
            records, meta = rebalance_map_polygons(
                source_polygons,
                black_vertices,
                params["snap_k"],
                params["small_factor"],
                params["large_factor"],
                self.log,
            )
            self.current_records = records
            self.last_snap_meta = meta
            self.last_after_stats = meta["after_stats"]
            self.export_all(outline_geometry, boundary_polygon, records, black_vertices, params)
            messagebox.showinfo("Done", "Run All completed.")
        except Exception as exc:
            self.log(f"ERROR: {exc}")
            self.log(log_exception_text())
            messagebox.showerror("Error", str(exc))


def main() -> None:
    root = tk.Tk()
    VoronoiSnapApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
