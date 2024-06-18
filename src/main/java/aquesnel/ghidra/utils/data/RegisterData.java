package aquesnel.ghidra.utils.data;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.LongBuffer;
import java.util.Arrays;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

public final class RegisterData extends AqDataStub implements Data {

	private final RegisterValue mRegisterValue;
	
	public RegisterData(RegisterValue register, DataType dataType, Program program) {
		
		super(null, dataType, program);
		mRegisterValue = Objects.requireNonNull(register);
	}
	
	@Override
	public Object getValue() {
		
		DataType dataType = getDataType();
		if(dataType instanceof AbstractIntegerDataType intDataType) {
			long longValue = intDataType.isSigned() 
					? mRegisterValue.getSignedValue().longValue() 
					: mRegisterValue.getUnsignedValue().longValue();
			
			return new Scalar(
					mRegisterValue.getRegister().getBitLength(), 
					longValue, 
					intDataType.isSigned());
			
//			> Error running script: TermminesPrintValues2.java
//			java.lang.NullPointerException: Cannot invoke "java.math.BigInteger.longValue()" because the return value of "ghidra.program.model.lang.RegisterValue.getSignedValue()" is null
//				at utils.RegisterData.getValue(RegisterData.java:48)
//				at utils.DataUtils.getValue(DataUtils.java:26)
//				at utils.DataUtils.toDebugInfo(DataUtils.java:55)
//				at TermminesPrintValues2.processBreakpoint(TermminesPrintValues2.java:378)
//				at TermminesPrintValues2.run(TermminesPrintValues2.java:163)
//				at ghidra.app.script.GhidraScript.executeNormal(GhidraScript.java:399)
//				at ghidra.app.script.GhidraScript.doExecute(GhidraScript.java:254)
//				at ghidra.app.script.GhidraScript.execute(GhidraScript.java:232)
//				at ghidra.app.plugin.core.script.RunScriptTask.run(RunScriptTask.java:47)
//				at ghidra.util.task.Task.monitoredRun(Task.java:134)
//				at ghidra.util.task.TaskRunner.lambda$startTaskThread$0(TaskRunner.java:106)
//				at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1136)
//				at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:635)
//				at java.base/java.lang.Thread.run(Thread.java:840)
		}
		else if (dataType instanceof PointerDataType pointerDataType) {
						
			return PointerDataType.getAddressValue(
					this, 
					getLength(), 
					getProgram().getAddressFactory().getAddressSpace("ram"));
			
//			Address pointer = (Address) pointerDataType.getValue(this, 
//					new DataTypeSettingsAdapter(mProgram.getDataTypeManager(), this), 
//					getLength());
//			if (pointer != null) {
//				return mProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pointer.getOffset());
//			}
//			return null;
		}
		throw new IllegalStateException("Unsuported DataType: " + dataType.toString() + " | " + dataType.getClass().getName());
	}
	
	@Override
	public String toString() {
		return "RegisterData {register = "
				+ getFieldName()
				+ ", DataType = "
				+ getDataType()
				+ ", value = "
//				+ mRegisterValue.toString()
				+ getValue()
				+ "}";
	}

	@Override
	public String getFieldName() {
		return mRegisterValue.getRegister().getName();
	}

	@Override
	public int getLength() {
		return mRegisterValue.getRegister().getBitLength() / 8;
	}

	@Override
	public byte[] getBytes() throws MemoryAccessException {
//		return mRegisterValue.toBytes(); // little endian
//		return mRegisterValue.getUnsignedValue().toByteArray(); // big endian
		
//		endianConverter = GhidraDataConverter.getInstance(false);
		byte[] temp = new byte[8];
		LongBuffer buffer = ByteBuffer.wrap(temp).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();
		buffer.put(mRegisterValue.getUnsignedValue().longValue());
		return Arrays.copyOf(temp, getLength());
	}

	@Override
	public boolean isBigEndian() {
//		return mRegisterValue.getRegister().isBigEndian();
		
		// Since we've hard coded the register value byte array to be little endian, we ignore the register's native endianess
		return false;
	}

	@Override
	public Address getAddress() {
		return mRegisterValue.getRegister().getAddress();
	}
}
