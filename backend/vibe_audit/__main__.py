import argparse
import os
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description="Start the local Vibe Audit workbench")
    parser.add_argument("--port",type=int,default=8000)
    parser.add_argument("--data-dir",default=None)
    args=parser.parse_args()
    # Catalogs, fixtures and the built UI sit beside backend/, so a copied wheel would run without its evidence base.
    if not (Path(__file__).resolve().parents[2]/"catalogs").is_dir():
        parser.exit(2,"Vibe Audit runs from its source checkout: start it with scripts/start-local.ps1 there, or pip install -e . in it\n")
    # Disable optional cloud tracing before loading orchestration libraries.
    os.environ["LANGCHAIN_TRACING_V2"]="false"
    os.environ["LANGSMITH_TRACING"]="false"
    os.environ["DO_NOT_TRACK"]="1"
    import uvicorn
    from .api import create_app
    from .diagnostics import configure
    from .settings import Settings
    # The port this launcher listens on is a trusted console origin beside whatever VIBEAUDIT_UI_ORIGINS names.
    app=create_app(settings=Settings.from_environ(data_dir=args.data_dir,console_origins_extra=[f"http://127.0.0.1:{args.port}",f"http://localhost:{args.port}"]))
    # Failures the API reports in fixed words are explained here, on this machine only (type and location, no values).
    configure(app.state.store.root)
    # The fragment never reaches the server or its logs; the workbench trades it for a session cookie.
    app.state.announce_token=lambda token:print(f"Vibe Audit workbench: http://127.0.0.1:{args.port}/#token={token}",flush=True)
    app.state.announce_token(app.state.session_token)
    uvicorn.run(app,host="127.0.0.1",port=args.port,access_log=False)


if __name__=="__main__":
    main()
