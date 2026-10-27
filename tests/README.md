# Offline regression tests (no game window)

`run_tests.ps1` builds the patch and a test DLL, then runs the test DLL **inside a copy of the unmodified game exe**
(`run\San9WPK.exe` imports `MyDoc.dll`; here `MyDoc.dll` is `tests.dll`). Its `DllMain` runs before the Steam stub / game code:
it overwrites the exe's memory with a snapshot taken from a live game (`snap.bin`), swaps the heap functions for a bump arena,
poses as the game's UI thread (MFC thread-state lookup), calls the game's own advisor and checks the patch logic against the
verdicts the real game recorded (`snap_truth.txt`). It then exits - the game never starts.

* `powershell -ExecutionPolicy Bypass -File run_tests.ps1` -> `ALL PASS` / `FAILED` (about 10 s)
* `python take_snapshot.py` -> refresh the snapshot (starts the game with `snapdll.dll`, slot 12; ~2 min; restores the patch DLL)
* Tests: `tests_body.inc` (sort_front stability, speed clock, advisor wrapper vs game, target marking incl. the "only another
  officer can recruit" regression). Add a case = add a `t_*` function and call it from `run_tests()`.
* Not covered: UI layout, clicks, the label drawing, real turn advance - smoke-test those in the game occasionally.
