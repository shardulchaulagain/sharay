# Desktop process lifetime

The desktop launcher owns the loopback API, and the API owns its dedicated worker. Each parent keeps the write end of a private stdin pipe; its child watches the read end only when the internal `--parent-stdin` flag is supplied. A killed parent closes the pipe through the operating system, so a detached child requests cooperative shutdown without polling a PID.

The API signals Uvicorn to finish its lifespan cleanup; the worker cancels its bounded request, records the interrupted work truthfully, and stops before claiming another queued assessment. Normal shutdown closes the pipe and retains the existing termination/deadline escalation. Explicitly marked startup requires a pipe. Standalone `serve` omits the flag and remains running when stdin is closed.

The watcher owns a duplicate of stdin, stops and joins before closing that descriptor, and never interprets data as commands. Broken channels or unexpected bytes request shutdown. API and supervisor database resources are disposed even when startup, shutdown or interruption bookkeeping raises.

Verification uses fresh temporary data and controlled loopback fixtures: launcher/API SIGKILL, early EOF, native closing events, browser interruption, smoke exit, standalone serve, active-request cancellation, queued-job preservation, invalid-channel refusal, duplicate locks, watcher cleanup and database failure paths. Tests signal only children they create. Gemini's non-server review and independent Codex review supplement these regressions.

This is cooperative POSIX lifecycle handling, verified on the development Mac. It is not a hard shutdown guarantee during an arbitrary deadlock, a Windows implementation, scanner isolation, or authorization to execute live assessments. A private pipe is a lifetime signal; it grants no assessment permissions.
