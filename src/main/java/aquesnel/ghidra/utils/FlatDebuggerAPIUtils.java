package aquesnel.ghidra.utils;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import aquesnel.ghidra.utils.data.MemoryData;
import aquesnel.ghidra.utils.data.RegisterData;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueUtils.VariableEvaluator;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer.LaunchResult;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet;
import ghidra.app.plugin.core.debug.stack.UnwoundFrame;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.app.services.TraceRecorder;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;

public class FlatDebuggerAPIUtils {


	public static FlatDebuggerAPI fromScript(GhidraScript script) {
		if (script instanceof FlatDebuggerAPI debugger) {
			return debugger;
		} else {
			return new GidraScriptFlatDebuggerAPI(script::getState);
		}
	}
	
	private static class GidraScriptFlatDebuggerAPI implements FlatDebuggerAPI
	{
		private final Supplier<GhidraState> mStateSupplier;
		
		private GidraScriptFlatDebuggerAPI(Supplier<GhidraState> supplier) {
			mStateSupplier = Objects.requireNonNull(supplier);
		}

		@Override
		public GhidraState getState() {

			return mStateSupplier.get();
		}
	}
	
	public static TraceRecorder launchOrGetCurrentTrace(GhidraScript script) throws Exception {
		FlatDebuggerAPI debugger = fromScript(script);
		TraceRecorder recorder = debugger.getCurrentRecorder();
		if(recorder != null && debugger.isTargetAlive()) {
			script.println("Continuing " + debugger.getCurrentProgram());
			return recorder;
		}
		
		script.println("Launching " + debugger.getCurrentProgram());
		LaunchResult result = debugger.launch(script.getMonitor());
		if (result.exception() == null) {
			return result.recorder();
		}

		script.printerr("Failed to launch " + debugger.getCurrentProgram() + ": " + result.exception());

		if (result.model() != null) {
			result.model().close();
		}

		if (result.recorder() != null) {
			debugger.closeTrace(result.recorder().getTrace());
		}
		if (result.exception() instanceof Exception e) {
			throw e;
		}
		throw new Exception("Wrapping non-Exception Throwable", result.exception());
	}
	
	public static Optional<LogicalBreakpoint> getCurrentBreakpoint(GhidraScript script) {
		FlatDebuggerAPI debugger = fromScript(script);
		Trace trace = debugger.getCurrentRecorder().getTrace();
		
		Address pc = debugger.getProgramCounter();
		for (Set<LogicalBreakpoint> breakpoints : debugger.getBreakpoints(debugger.getCurrentProgram()).values()) {
			for (LogicalBreakpoint breakpoint : breakpoints) {
				if (pc.equals(breakpoint.getTraceAddress(trace))) {
					return Optional.of(breakpoint);
				}
			}
		}
		return Optional.empty();
	}
	
	public static Optional<String> getCurrentPreComment(GhidraScript script) {
		FlatDebuggerAPI debugger = fromScript(script);
		
		Address dynamicPc = debugger.getProgramCounter();
		Address staticPc = debugger.translateDynamicToStatic(dynamicPc);
		String comment = script.getPreComment(staticPc);
		return Optional.ofNullable(comment);
	}
	
	public static LogicalBreakpoint setOrGetBreakpoint(FlatDebuggerAPI debugger, ProgramLocation location, String name) {
		
		TraceRecorder recorder = debugger.getCurrentRecorder();
		if(recorder == null) {
			throw new IllegalStateException("breakpoints must be set after the recorder exists.");
		}
		
		DebuggerLogicalBreakpointService service = debugger.getBreakpointService();
		
		Optional<LogicalBreakpoint> existingBreakpoint = expectOnlyOne(service.getBreakpointsAt(location)
				.stream()
				.filter(b -> Objects.equals(name, b.getName()))
				.collect(Collectors.toSet()));
		
		if (existingBreakpoint.isPresent()) {
//			service.enableAll()
			return existingBreakpoint.get();
		}
		
		Optional<LogicalBreakpoint> newBreakpoint = 
				expectOnlyOne(debugger.breakpointSetSoftwareExecute(location, name));
		
		return newBreakpoint.orElseThrow();
	}
	
	private static <T> Optional<T> expectOnlyOne(Collection<T> items) {
		if (items.isEmpty()) {
			return Optional.empty();
		}

		if (items.size() > 1) {
			throw new IllegalStateException(
					"There are multiple items but only one expected. Items: " 
							+ items);
		}

		return Optional.of(items.iterator().next()); 
	}
	
//	public static void enableBreakpoint() {
//	
//	}
	
	public static byte[] readMemoryBytes(GhidraScript script, Address address, int length) {
		while (!script.getMonitor().isCancelled()) {
			FlatDebuggerAPI debugger = fromScript(script);
			
			try {
				Address dynamicAddress = toDynamicAddress(script, address.getPhysicalAddress());
				return debugger.readMemory(dynamicAddress, length, script.getMonitor());
			}
			catch (AccessPcodeExecutionException e) {
				// the timeout for reading memory is hard coded to 1 sec, which sometimes fails. 
				// So we will continue until the user cancels the request
				// see {@link ghidra.app.plugin.core.debug.service.emulation.AbstractRWTargetPcodeExecutorStatePiece$AbstractRWTargetCachedSpace#waitTimeout()} AbstractRWTargetPcodeExecutorStatePiece.java:71
				if (e.getCause() instanceof TimeoutException) {
					continue;
				}
				throw e;
			}
		}
		throw new RuntimeException(new InterruptedException("The Monitor is now in the canceled state."));
	}
	
	public static Data readRegister(GhidraScript script, String registerName) {

		FlatDebuggerAPI debugger = fromScript(script);
		return new RegisterData(
				debugger.readRegister(registerName),
				new UnsignedIntegerDataType(),
				script.getCurrentProgram());
	}
	
	public static Optional<Data> readGlobalSymbol(GhidraScript script, String name) {
		List<Symbol> symbols = script.getSymbols(name, null);
		Symbol dataSymbol;
		
		if (symbols.size() == 0) {
			return Optional.empty();
		}
		else if (symbols.size() == 1) {
			dataSymbol = symbols.get(0);
		}
		else {
			throw new IllegalStateException(
				"There are " + Integer.toString(symbols.size())+ " symbols named '" + name + "' in namespace (GLOBAL)");
		}
		
		return Optional.ofNullable(script.getDataAt(toDynamicAddress(script, dataSymbol.getAddress())));
	}
	
	public static Data dereferencePointer(GhidraScript script, Data pointer) {
		
//		throw new UnsupportedOperationException("TODO");
		if(!(pointer.getBaseDataType() instanceof Pointer pointerType)) {
			throw new IllegalArgumentException(
					"Expected a Pointer DataType, got: " 
					+ pointer.getBaseDataType().toString());
		}
		
		Object result = pointer.getValue();
//		script.println("deref: pointer = " + pointer.toString());
		Address address;
		if (result instanceof Scalar s) {
			address = script.getAddressFactory()
							.getAddressSpace("ram")
//							.getDefaultAddressSpace()
							.getAddress(s.getValue());
		}
		else if (result instanceof Address a) {
			address = a;
		}
		else {
			throw new IllegalArgumentException("pointer is not a valid address type");
		}
		
		Address dynamicAddress = toDynamicAddress(script, address);
//		script.println("deref: original address = " + address.toString());
//		script.println("deref: dynamic  address = " + dynamicAddress.toString());
		
		DataType referredDataType = pointerType.getDataType();
//		if (referredDataType instanceof Array arrayDataType) {
//			// when dereferencing an array, the change the datatype to the array's element data type
//			referredDataType = arrayDataType.getDataType();
//		}
		
		Data dataAt = new MemoryData(dynamicAddress, referredDataType, script.getCurrentProgram(), script); 
		//script.getDataAt(dynamicAddress);
//		script.println("deref: pointer result = " + Objects.toString(dataAt, "<null>"));
		return dataAt;
	}
	
	public static Address stackToMemAddress(GhidraScript script, Address stackAddress) {
		
		if (!stackAddress.isStackAddress()) {
			throw new IllegalArgumentException("Expected a Stack based address, but got: " + stackAddress.toString());
		}
		FlatDebuggerAPI debugger = fromScript(script);
//			DebuggerTraceManagerService traceManager = script.getState().getTool().getService(DebuggerTraceManagerService.class);
		DebuggerCoordinates coordonates = debugger.getCurrentDebuggerCoordinates();
		VariableEvaluator eval = new VariableEvaluator(script.getState().getTool(), coordonates);
		Function function = script.getFunctionContaining(debugger.translateDynamicToStatic(debugger.getProgramCounter()));
//		script.println("Got function: " + function.toString());
		
		UnwoundFrame<WatchValue> frame =
				eval.getStackFrame(function, new StackUnwindWarningSet(), script.getMonitor(), true);
//		script.println("Got frame: " + frame.toString());
		
		Address dynAddr = frame.getBasePointer().add(stackAddress.getOffset());
		return dynAddr;
	}
	
	public static Address toDynamicAddress(GhidraScript script, Address staticAddress) {
		FlatDebuggerAPI debugger = fromScript(script);
		if (staticAddress.isUniqueAddress()
				|| staticAddress.isRegisterAddress()) {
			return staticAddress;
		}
		else if (staticAddress.isStackAddress()) {
			return stackToMemAddress(script, staticAddress);
		}
		
		Address dynamicAddress = debugger.translateStaticToDynamic(staticAddress);
		if (dynamicAddress != null) {
			return dynamicAddress;
		}
		return staticAddress;
	}
	
//	record MappedLocation(Program stProg, Address stAddr, Address dynAddr) {
//	}
//
//	/*
//	 * Copied from {@link ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueHoverService}
//	 */
//	protected MappedLocation mapLocation(GhidraScript script, Program programOrView, Address address, DebuggerCoordinates current) {
//		PluginTool tool = script.getState().getTool();
//		DebuggerStaticMappingService mappingService = tool.getService(DebuggerStaticMappingService.class);
//		if (programOrView instanceof TraceProgramView view) {
//			ProgramLocation stLoc =
//				mappingService.getStaticLocationFromDynamic(new ProgramLocation(view, address));
//			return stLoc == null
//					? new MappedLocation(null, null, address)
//					: new MappedLocation(stLoc.getProgram(), stLoc.getAddress(), address);
//		}
//		ProgramLocation dynLoc = mappingService.getDynamicLocationFromStatic(current.getView(),
//			new ProgramLocation(programOrView, address));
//		return new MappedLocation(programOrView, address,
//			dynLoc == null ? null : dynLoc.getAddress());
//	}
}
