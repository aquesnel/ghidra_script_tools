package aquesnel.ghidra.debugger.breaklang;


import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import aquesnel.ghidra.utils.FlatDebuggerAPIUtils;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;

public class Breaklang {

	private static final boolean FORCE_VERBOSE = false;
	private static final boolean ENABLE_MESSAGE_PREFIX = false;
	
	public static void runBreaklangLoop(GhidraScript script) throws Exception {
		FlatDebuggerAPI debugger = FlatDebuggerAPIUtils.fromScript(script);
		/**
		 * Here we'll just launch the current program. Note that this is not guaranteed to succeed
		 * at all. Launching is subject to an opinion-based service. If no offers are made, this
		 * will fail. If the target system is missing required components, this will fail. If the
		 * target behaves in an unexpected way, this may fail. One example is targets without an
		 * initial break. If Ghidra does not recognize the target platform, this will fail. Etc.,
		 * etc., this may fail.
		 * 
		 * In the event of failure, nothing is cleaned up automatically, since in some cases, the
		 * user may be expected to intervene. In our case; however, there's no way to continue this
		 * script on a repaired target, so we'll close the connection on failure. An alternative
		 * design for this script would expect the user to have already launched a target, and it
		 * would just operate on the "current target."
		 */
//		script.println("Launching " + script.getCurrentProgram());
		Trace trace = FlatDebuggerAPIUtils.launchOrGetCurrentTrace(script).getTrace();
//		script.println("Successfully launched in trace " + trace);

		/**
		 * Breakpoints are highly dependent on the module map. To work correctly: 1) The target
		 * debugger must provide the module map. 2) Ghidra must have recorded that module map into
		 * the trace. 3) Ghidra must recognize the module names and map them to programs open in the
		 * tool. These events all occur asynchronously, usually immediately after launch. Most
		 * launchers will wait for the target program module to be mapped to its Ghidra program
		 * database, but the breakpoint service may still be processing the new mapping.
		 */
		debugger.flushAsyncPipelines(trace);
		
//		script.println("Program Type: " + script.getCurrentProgram().getClass().getName());
//		script.println("Trace Type: " + trace.getClass().getName());
//		script.println("Trace Program Type: " + trace.getProgramView().getClass().getName());
//		
//		script.println("Address spaces ProgramDB:");
//		for (AddressSpace a : script.getCurrentProgram().getAddressFactory().getAllAddressSpaces()) {
//			script.print(a.toString());
//			script.print(" ");
//			script.print(Integer.toString(a.getSpaceID()));
//			script.print(" ");
//			script.print(Integer.toString(a.getType()));
//			script.print(" ");
//			script.print(a.getClass().getName());
//			script.print("\n");
//		}
//		script.println("---");
//		script.println("Address spaces TraceProgram:");
//		for (AddressSpace a : trace.getProgramView().getAddressFactory().getAllAddressSpaces()) {
//			script.print(a.toString());
//			script.print(" ");
//			script.print(Integer.toString(a.getSpaceID()));
//			script.print(" ");
//			script.print(Integer.toString(a.getType()));
//			script.print(" ");
//			script.print(a.getClass().getName());
//			script.print("\n");
//		}
//		script.println("---");
		
		
		/**
		 * This runs the target, recording memory around the PC and SP at each break, until it
		 * terminates.
		 */
		try
		{
			int breakCount = 0;
			BreaklangEvaluator.EvaluationContext context = 
					new BreaklangEvaluator.EvaluationContext(script);
			BreaklangParser parser = new BreaklangParser();
			
			Optional<LogicalBreakpoint> initialBreakpoint = FlatDebuggerAPIUtils.getCurrentBreakpoint(script);
			TargetExecutionState executionState = debugger.getExecutionState(trace);
			script.println("target status: " + executionState);

			if (initialBreakpoint
						.map(b -> !b.computeStateForTrace(trace).isEnabled())
						.orElse(true)
					&& !executionState.isRunning()) {
				script.println("Target is stopped and not at an enabled breakpoint, resuming...");
				resumeScript(script, debugger, context);
				debugger.flushAsyncPipelines(trace);
			}
			
			while (debugger.isTargetAlive()
					&& !script.getMonitor().isCancelled()) {
				
				/**
				 * The recorder is going to schedule some reads upon break, so let's allow them to
				 * settle.
				 */
				debugger.waitForBreak(10, TimeUnit.SECONDS);
				debugger.flushAsyncPipelines(trace);

				breakCount += 1;
				String msgPrefix;
				if (ENABLE_MESSAGE_PREFIX) {
					msgPrefix = "[" + breakCount + "] ";
				}
				else {
					msgPrefix = "";
				}
				Address pcDynamic = debugger.getProgramCounter();
				Address pcStatic = debugger.translateDynamicToStatic(pcDynamic);
				Optional<LogicalBreakpoint> optBreakpoint = FlatDebuggerAPIUtils.getCurrentBreakpoint(script);
								
				if (optBreakpoint.isEmpty()) {
					script.println(msgPrefix + "Non-Breaklang breakpoint at PC = " + pcDynamic + " (dynamic) / " + pcStatic + " (static)");
					script.println(msgPrefix + "--- Breaking ---");
					break;
				
				} else {
					LogicalBreakpoint breakpoint = optBreakpoint.get();
					String breakpointName = breakpoint.getName();
					
					try {
						BreaklangParseResult parseResult = parser.parse(breakpointName);
						BreaklangEvaluator.evaluateParseResult(context, parseResult);
						if (FORCE_VERBOSE) {
							context.withVerbose(true);
						}
						
						if (context.verbose()) {
							script.println(msgPrefix + "Breakpoint at PC = " + pcDynamic + " (dynamic) / " + pcStatic + " (static)" + " | " + breakpointName);
						}
						
						if (parseResult.parseComment()) {
							Optional<String> comment = FlatDebuggerAPIUtils.getCurrentPreComment(script);
							if (context.verbose()) {
								script.println(msgPrefix + "PreComment at PC = " + pcDynamic + " (dynamic) / " + pcStatic + " (static)" + " | " + comment.orElse("<none>"));
							}
							if (comment.isPresent()) {
								boolean breakpointIsBreak = context.isBreak();
								boolean breakpointVerbose = context.verbose();
								String breakpointMessage = context.message();
								
								try {
									parseResult = parser.parse(comment.get());
									BreaklangEvaluator.evaluateParseResult(context, parseResult);
								}
								catch (RuntimeException e) {
									throw new RuntimeException(
											"Processing Breaklang PreComment with PC = " + pcDynamic + " (dynamic) / " + pcStatic + " (static)" + " | " + comment.orElse("<none>"),
											e);
								}
								
								context.withBreak(breakpointIsBreak && context.isBreak());
								context.withVerbose(breakpointVerbose || context.verbose());
								context.withMessage(breakpointMessage + "\n" + context.message());
							}
						}
						String strippedMessage = context.message().replaceAll("\\\\n", "\n").strip();
						if (!strippedMessage.isEmpty()) {
							script.println(strippedMessage);
						}
					}
					catch (RuntimeException e) {
						throw new RuntimeException(
								"Processing Breaklang breakpoint with PC = " + pcDynamic + " (dynamic) / " + pcStatic + " (static)" + " | " + breakpointName,
								e);
					}
				}
				
				if (context.isBreak()) {
					if (context.verbose()) {
						script.println(msgPrefix + "--- Breaking ---");
					}
					break;
				}
				if (context.verbose()) {
					script.println(msgPrefix + "--- Resuming ---");
				}
				resumeScript(script, debugger, context);
			}
		}
		catch (TimeoutException e)
		{
			script.println("Breaklang timeout exceeded");
		}
		script.println("Breaklang Terminated");
	}
	
	private static void resumeScript(GhidraScript script, FlatDebuggerAPI debugger, BreaklangEvaluator.EvaluationContext context) throws InterruptedException {
		
//		boolean resumeresult = debugger.resume();
//		Thread.sleep(10); // resume is async, and there is no API for waiting on it, so just try to sleep to let the resume happen
//		script.println("resume status: " + Boolean.toString(resumeresult));
		
//		if (win32) {
			String dbgEngOutput = debugger.executeCapture("g");
			if (context.verbose()) {
				script.println("[[dbgEng]] " + dbgEngOutput);
			}
//		}
		
//		debugger.executeCapture("-exec-continue");
//		if (linux) {
//			String gdbOutput = debugger.executeCapture("continue");
//			if (context.verbose()) {
//				script.println("[[gdb]] " + gdbOutput);
//			}
//		}
	}
}
