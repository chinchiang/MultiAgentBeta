import argparse
import os


def main():
    parser=argparse.ArgumentParser(description="Start the local Vibe Audit workbench")
    parser.add_argument("--port",type=int,default=8000)
    parser.add_argument("--data-dir",default=None)
    args=parser.parse_args()
    # Disable optional cloud tracing before loading orchestration libraries.
    os.environ["LANGCHAIN_TRACING_V2"]="false"
    os.environ["LANGSMITH_TRACING"]="false"
    os.environ["DO_NOT_TRACK"]="1"
    if args.data_dir:
        os.environ["VIBEAUDIT_DATA_DIR"]=args.data_dir
    configured=[s for s in os.getenv("VIBEAUDIT_UI_ORIGINS","").split(",") if s]
    os.environ["VIBEAUDIT_UI_ORIGINS"]=",".join(dict.fromkeys(configured+[f"http://127.0.0.1:{args.port}",f"http://localhost:{args.port}"]))
    import uvicorn
    from .api import create_app
    app=create_app()
    # The fragment never reaches the server or its logs; the workbench trades it for a session cookie.
    print(f"Vibe Audit workbench: http://127.0.0.1:{args.port}/#token={app.state.session_token}",flush=True)
    uvicorn.run(app,host="127.0.0.1",port=args.port,access_log=False)


if __name__=="__main__":
    main()
