package aquesnel.ghidra.utils.data;

import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public abstract class AqDataStub implements Data, MixinDataSettings, MixinStubData {

	private final Optional<Data> mParent;
	private final DataType mDataType;
	private final Program mProgram;

	public AqDataStub(Data parent, DataType dataType, Program program) {

		mParent = Optional.ofNullable(parent);
		mDataType = Objects.requireNonNull(dataType);
		mProgram = Objects.requireNonNull(program);
	}

	@Override
	public int getLength() {
		return mDataType.getLength();
	}

	@Override
	public DataType getDataType() {
		return mDataType;
	}

	@Override
	public DataType getBaseDataType() {
		return DataUtils.getBaseDataType(this);
	}

	@Override
	public Program getProgram() {
		return mProgram;
	}

	@Override
	public Memory getMemory() {
		return mProgram.getMemory();
	}

	@Override
	public boolean isWritable() {
		return mParent.map(Data::isWritable).orElse(false);
	}

	@Override
	public Data getParent() {
		return mParent.orElse(null);
	}

	@Override
	public Data getDataForSettings() {
		return this;
	}

	/**
	 * Copied from {@link ghidra.program.database.code.DataDB#getNumComponents()}
	 */
	@Override
	public int getNumComponents() {
		if (getLength() < mDataType.getLength()) {
			return -1;
		}

		DataType baseDataType = getBaseDataType();
		if (baseDataType  instanceof Composite) {
			return ((Composite) baseDataType).getNumComponents();
		}
		else if (baseDataType instanceof Array) {
			return ((Array) baseDataType).getNumElements();
		}
		else if (baseDataType instanceof DynamicDataType) {
			try {
				return ((DynamicDataType) baseDataType).getNumComponents(this);
			}
			catch (Throwable t) {
				//Msg.error(this,
				//	"Data type error (" + baseDataType.getName() + "): " + t.getMessage(), t);
//				return 0;
				throw new IllegalStateException(t);
			}
		}
		return 0;
	}

	@Override
	public Data getComponent(int index) {

		return new AqDataComponent(this, index);
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		return getBytes()[offset];
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		try {
			byte[] srcBytes = getBytes();
			int copyLength = Math.min(srcBytes.length, b.length);
			System.arraycopy(
					srcBytes,
					offset,
					b,
					0,
					copyLength);
			return copyLength;
		}
		catch (MemoryAccessException e) {
			return 0;
		}
	}

	@Override
	public Object getValue() {
		return DataUtils.getValue(this);
	}
}
