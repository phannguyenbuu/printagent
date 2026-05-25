from agent.web_ftp import register_ftp_routes


def register_scan_ftp_routes(app):
    register_ftp_routes(app)
    try:
        from agent.web_scan import register_scan_routes
        register_scan_routes(app)
    except ImportError:
        pass
