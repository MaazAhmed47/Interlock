@echo off
cd D:\Interlock
call venv\Scripts\activate
uvicorn proxy:app --host 0.0.0.0 --port 8001