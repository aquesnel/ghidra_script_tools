package aquesnel.ghidra.utils.data;

import java.util.Objects;

import aquesnel.ghidra.utils.FlatDebuggerAPIUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class MemoryData extends AqDataStub implements Data {

	private final Address mAddress;
	private final GhidraScript mScript;
	
	public MemoryData(Address address, DataType dataType, Program program, GhidraScript script) {
		
		super(null, dataType, program);
		mAddress = Objects.requireNonNull(address);
		mScript = Objects.requireNonNull(script);
		
//		//TODO: I don't know how to read values from unique, even though the built-in debugger has code to do it
//		// {@link ghidra.app.plugin.core.debug.gui.watch.WatchRow#reevaluate()}
//		if (mAddress.isUniqueAddress() ) {
//			throw new IllegalArgumentException("MemoryData does not support the 'Unique' address space.");
//		}
//		if (mAddress.isRegisterAddress() ) {
//			throw new IllegalArgumentException("MemoryData does not support the 'Register' address space.");
//		}
		if (!mAddress.isMemoryAddress() && !mAddress.isStackAddress()) {
			throw new IllegalArgumentException("MemoryData only supports the 'Memory' and 'Stack' address spaces. Got: " + mAddress.toString());
		}
	}
	
	@Override
	public String toString() {
		return "MemoryData {Address = "
				+ mAddress.toString()
				+ ", DataType = "
				+ getDataType()
				+ ", value = "
				+ Objects.toString(getValue(), "<null>")
				+ "}";
	}

	@Override
	public String getFieldName() {
		return "[mem @ " + mAddress.toString() + "]";
	}

	@Override
	public Address getAddress() {
		return mAddress;
	}
	
	@Override
	public byte[] getBytes() throws MemoryAccessException {
		return FlatDebuggerAPIUtils.readMemoryBytes(mScript, mAddress, getDataType().getLength());
	}

	@Override
	public boolean isBigEndian() {
		return getProgram().getMemory().isBigEndian();
	}
	
//	@Override
//	public Object getValue() {
//		
//		//TODO: I don't know how to read values from unique, even though the built-in debugger has code to do it
//		// {@link ghidra.app.plugin.core.debug.gui.watch.WatchRow#reevaluate()}
//		if (mAddress.isUniqueAddress() ) {// || address.isStackAddress()) {
//			return null;
//		}
//		Address address = FlatDebuggerAPIUtils.toDynamicAddress(mScript, mAddress.getPhysicalAddress());
//		
//		byte[] bytes;
//		boolean isBigEndian;
//		{
//			FlatDebuggerAPI debugger = FlatDebuggerAPIUtils.fromScript(mScript);
//			bytes = debugger.readMemory(address, getDataType().getLength(), mScript.getMonitor());
//			isBigEndian = getProgram().getMemory().isBigEndian();
////		
////			> Error running script: TermminesPrintValues3.java
////			java.lang.IllegalArgumentException: Address must be in memory or NO_ADDRESS. Got stack:
////				at ghidra.trace.database.space.DBTraceDelegatingManager.checkIsInMemory(DBTraceDelegatingManager.java:45)
////				at ghidra.trace.database.space.DBTraceDelegatingManager.delegateReadI(DBTraceDelegatingManager.java:126)
////				at ghidra.trace.database.memory.DBTraceMemoryManager.getViewBytes(DBTraceMemoryManager.java:351)
////				at ghidra.debug.flatapi.FlatDebuggerAPI.readMemory(FlatDebuggerAPI.java:853)
////				at ghidra.debug.flatapi.FlatDebuggerAPI.readMemory(FlatDebuggerAPI.java:869)
////				at ghidra.debug.flatapi.FlatDebuggerAPI.readMemory(FlatDebuggerAPI.java:898)
////				at utils.MemoryData.getValue(MemoryData.java:43)
////				at utils.DataUtils.getValue(DataUtils.java:32)
////				at java.base/java.util.Optional.map(Optional.java:260)
////				at aquesnel.ghidra.debugger.breaklang.BreaklangEvaluator.evaluatePrintLocals(BreaklangEvaluator.java:231)
////				at aquesnel.ghidra.debugger.breaklang.BreaklangEvaluator.evaluateParseResult(BreaklangEvaluator.java:92)
////				at aquesnel.ghidra.debugger.breaklang.Breaklang.runBreaklangLoop(Breaklang.java:124)
////				at TermminesPrintValues3.run(TermminesPrintValues3.java:16)
////				at ghidra.app.script.GhidraScript.executeNormal(GhidraScript.java:399)
////				at ghidra.app.script.GhidraScript.doExecute(GhidraScript.java:254)
////				at ghidra.app.script.GhidraScript.execute(GhidraScript.java:232)
////				at ghidra.app.plugin.core.script.RunScriptTask.run(RunScriptTask.java:47)
////				at ghidra.util.task.Task.monitoredRun(Task.java:134)
////				at ghidra.util.task.TaskRunner.lambda$startTaskThread$0(TaskRunner.java:106)
////				at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1136)
////				at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:635)
////				at java.base/java.lang.Thread.run(Thread.java:833)
//		}
//		
//		{
////			ByteBuffer buf = ByteBuffer.allocate(getLength());
////			TraceProgramView trace = ((TraceProgramView)getProgram());
////			Trace t = (Trace) trace;
////			t.getMemoryManager().getViewBytes(t.getTimeManager().getMaxSnap(), mAddress, buf);
////			byte[] bytes = buf.array();
////			boolean isBigEndian = true; // ByteBuffer.allocate() is defined to use BigEndian-ness
//			
////			class ghidra.program.database.ProgramDB cannot be cast to class ghidra.trace.model.program.TraceProgramView (ghidra.program.database.ProgramDB and ghidra.trace.model.program.TraceProgramView are in unnamed module of loader ghidra.GhidraClassLoader @68f7aae2)
////			java.lang.ClassCastException: class ghidra.program.database.ProgramDB cannot be cast to class ghidra.trace.model.program.TraceProgramView (ghidra.program.database.ProgramDB and ghidra.trace.model.program.TraceProgramView are in unnamed module of loader ghidra.GhidraClassLoader @68f7aae2)
////				at utils.MemoryData.getValue(MemoryData.java:74)
////				at utils.DataUtils.getValue(DataUtils.java:32)
////				at java.base/java.util.Optional.map(Optional.java:260)
////				at aquesnel.ghidra.debugger.breaklang.BreaklangEvaluator.evaluatePrintLocals(BreaklangEvaluator.java:231)
////				at aquesnel.ghidra.debugger.breaklang.BreaklangEvaluator.evaluateParseResult(BreaklangEvaluator.java:92)
////				at aquesnel.ghidra.debugger.breaklang.Breaklang.runBreaklangLoop(Breaklang.java:124)
////				at TermminesPrintValues3.run(TermminesPrintValues3.java:16)
////				at ghidra.app.script.GhidraScript.executeNormal(GhidraScript.java:399)
////				at ghidra.app.script.GhidraScript.doExecute(GhidraScript.java:254)
////				at ghidra.app.script.GhidraScript.execute(GhidraScript.java:232)
////				at ghidra.app.plugin.core.script.RunScriptTask.run(RunScriptTask.java:47)
////				at ghidra.util.task.Task.monitoredRun(Task.java:134)
////				at ghidra.util.task.TaskRunner.lambda$startTaskThread$0(TaskRunner.java:106)
////				at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1136)
////				at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:635)
////				at java.base/java.lang.Thread.run(Thread.java:833)
//		}
//		
//		{
////			PcodeExecutorState<byte[]> mem = DebuggerPcodeUtils.executorStateForCoordinates(
////					mScript.getState().getTool(),
////					DebuggerCoordinates.NOWHERE.trace(
////							FlatDebuggerAPIUtils.fromScript(mScript).getCurrentRecorder().getTrace()));
////			bytes = mem.getVar(address, getLength(), true, Reason.INSPECT);
////			isBigEndian = getProgram().getMemory().isBigEndian();
//			
////			Address must be in memory or NO_ADDRESS. Got stack:
////				java.lang.IllegalArgumentException: Address must be in memory or NO_ADDRESS. Got stack:
////					at ghidra.trace.database.space.DBTraceDelegatingManager.checkIsInMemory(DBTraceDelegatingManager.java:45)
////					at ghidra.trace.database.space.DBTraceDelegatingManager.delegateReadOr(DBTraceDelegatingManager.java:104)
////					at ghidra.trace.database.memory.DBTraceMemoryManager.doGetStates(DBTraceMemoryManager.java:315)
////					at ghidra.trace.database.memory.DBTraceMemorySpace.doGetStates(DBTraceMemorySpace.java:462)
////					at ghidra.trace.database.memory.DBTraceMemorySpace.getAddressesWithState(DBTraceMemorySpace.java:445)
////					at ghidra.trace.database.memory.DBTraceMemoryManager.lambda$getAddressesWithState$18(DBTraceMemoryManager.java:295)
////					at ghidra.trace.database.space.DBTraceDelegatingManager.delegateAddressSet(DBTraceDelegatingManager.java:250)
////					at ghidra.trace.database.memory.DBTraceMemoryManager.getAddressesWithState(DBTraceMemoryManager.java:294)
////					at ghidra.trace.model.memory.TraceMemoryOperations.getAddressesWithState(TraceMemoryOperations.java:282)
////					at ghidra.pcode.exec.trace.data.AbstractPcodeTraceDataAccess.intersectUnknown(AbstractPcodeTraceDataAccess.java:173)
////					at ghidra.app.plugin.core.debug.service.emulation.RWTargetMemoryPcodeExecutorStatePiece$RWTargetMemoryCachedSpace.readUninitializedFromTarget(RWTargetMemoryPcodeExecutorStatePiece.java:92)
////					at ghidra.app.plugin.core.debug.service.emulation.AbstractRWTargetPcodeExecutorStatePiece$AbstractRWTargetCachedSpace.readUninitializedFromBacking(AbstractRWTargetPcodeExecutorStatePiece.java:60)
////					at ghidra.pcode.exec.BytesPcodeExecutorStateSpace.read(BytesPcodeExecutorStateSpace.java:182)
////					at ghidra.pcode.exec.AbstractBytesPcodeExecutorStatePiece.getFromSpace(AbstractBytesPcodeExecutorStatePiece.java:154)
////					at ghidra.pcode.exec.AbstractBytesPcodeExecutorStatePiece.getFromSpace(AbstractBytesPcodeExecutorStatePiece.java:36)
////					at ghidra.pcode.exec.AbstractLongOffsetPcodeExecutorStatePiece.getVar(AbstractLongOffsetPcodeExecutorStatePiece.java:324)
////					at ghidra.pcode.exec.DefaultPcodeExecutorState.getVar(DefaultPcodeExecutorState.java:74)
////					at ghidra.pcode.emu.ThreadPcodeExecutorState.getVar(ThreadPcodeExecutorState.java:112)
////					at ghidra.pcode.exec.PcodeExecutorStatePiece.getVar(PcodeExecutorStatePiece.java:237)
////					at utils.MemoryData.getValue(MemoryData.java:116)
////					at utils.DataUtils.getValue(DataUtils.java:32)
////					at java.base/java.util.Optional.map(Optional.java:260)
////					at aquesnel.ghidra.debugger.breaklang.BreaklangEvaluator.evaluatePrintLocals(BreaklangEvaluator.java:231)
////					at aquesnel.ghidra.debugger.breaklang.BreaklangEvaluator.evaluateParseResult(BreaklangEvaluator.java:92)
////					at aquesnel.ghidra.debugger.breaklang.Breaklang.runBreaklangLoop(Breaklang.java:124)
////					at TermminesPrintValues3.run(TermminesPrintValues3.java:16)
////					at ghidra.app.script.GhidraScript.executeNormal(GhidraScript.java:399)
////					at ghidra.app.script.GhidraScript.doExecute(GhidraScript.java:254)
////					at ghidra.app.script.GhidraScript.execute(GhidraScript.java:232)
////					at ghidra.app.plugin.core.script.RunScriptTask.run(RunScriptTask.java:47)
////					at ghidra.util.task.Task.monitoredRun(Task.java:134)
////					at ghidra.util.task.TaskRunner.lambda$startTaskThread$0(TaskRunner.java:106)
////					at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1136)
////					at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:635)
////					at java.base/java.lang.Thread.run(Thread.java:833)
//
//		}
//		
//		{
////			executeBackground(monitor -> {
////				UnwoundFrame<WatchValue> frame =
////					eval.getStackFrame(function, warnings, monitor, true);
////				
////
////				
////				WatchValue value = frame.getValue(program, storage);
////				return new BytesRow(value);
//////				return fillFrameStorage(frame, variable.getName(), variable.getDataType(),
//////					variable.getProgram(), variable.getVariableStorage());
////			});
////			
////			Address dynAddr = frame.getBasePointer().add(stackAddress.getOffset());
////			DebuggerCoordinates current;
////			TraceData dynData;
////			Address stAddr;
////			Program stProg;
////			CodeUnit stUnit = stProg.getListing().getCodeUnitAt(stAddr);
////			if (stUnit == null) {
////				return fillDefinedData(dynData);
////			}
////			if (stUnit instanceof Data stData) {
////				AddressRange dynRange = new AddressRangeImpl(dynData.getMinAddress(),
////					dynData.getMinAddress().add(stData.getLength() - 1));
////				BytesRow bytesRow =
////						BytesRow.fromRange(current.getPlatform(), dynRange, current.getViewSnap());
//////				BytesRow bytesRow = BytesRow.fromCodeUnit(dynData, current.getViewSnap());
////				
////				long size = dynRange.getLength();
////				ByteBuffer buf = ByteBuffer.allocate((int) size);
////				Trace trace = current.getPlatform().getTrace();
////				if (size != trace.getMemoryManager().getViewBytes(current.getViewSnap(), dynRange.getMinAddress(), buf)) {
////					throw new AssertionError(new MemoryAccessException("Could not read bytes"));
////				}
////				
////				bytes = buf.array();
////				isBigEndian = getProgram().getMemory().isBigEndian();
////			}
////			
////			//
////			
////			TraceCodeUnitsView codeUnits = current.getTrace().getCodeManager().codeUnits();
////			TraceCodeUnit unitAfterUpdate =
////					codeUnits.getContaining(current.getViewSnap(), mapped.dynAddr);
////			fillCodeUnit(unitAfterUpdate, mapped.stProg, mapped.stAddr);
//		}
//		
//		return getDataType().getValue(
//				new ByteMemBufferImpl(address, bytes, isBigEndian), 
//				new DataTypeSettingsAdapter(getProgram().getDataTypeManager(), this), 
//				getLength());	
//
////		return getDataType().getValue(
////				new MemoryBufferImpl(getProgram().getMemory(), mAddress), 
////				new DataTypeSettingsAdapter(getProgram().getDataTypeManager(), this), 
////				getLength());			
//	}
}
