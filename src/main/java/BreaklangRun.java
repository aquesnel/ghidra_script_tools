//
//@author 
//@category BreakLang
//@keybinding
//@menupath
//@toolbar

import aquesnel.ghidra.debugger.breaklang.Breaklang;
import ghidra.app.script.GhidraScript;
import ghidra.debug.flatapi.FlatDebuggerAPI;

public class BreaklangRun extends GhidraScript implements FlatDebuggerAPI {

	@Override
	protected void run() throws Exception {
		Breaklang.runBreaklangLoop(this);
		println("Script Terminated");
	} 
}
