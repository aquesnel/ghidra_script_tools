package aquesnel.ghidra.utils.data;

import java.util.Arrays;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public final class BytesData extends AqDataStub implements Data {
	private final byte[] mValue;
	private final boolean mIsBigEndian;
	private final Address mAddress;
	
	public BytesData(byte[] value, boolean isBigEndian, DataType dataType, Program program) {
		this(
				value, 
				isBigEndian, 
				GenericAddress.NO_ADDRESS, 
				dataType, 
				program);
	}
	
	public BytesData(byte[] value, boolean isBigEndian, Address address, DataType dataType, Program program) {
		super(null, dataType, program);
		mValue = Objects.requireNonNull(value);
		mIsBigEndian = isBigEndian;
		mAddress = Objects.requireNonNull(address);
	}
	
	@Override
	public byte[] getBytes() throws MemoryAccessException {
		return Arrays.copyOf(mValue, mValue.length);
	}

	@Override
	public boolean isBigEndian() {
		return mIsBigEndian;
	}
	
	@Override
	public String toString() {
		return "BytesData {DataType = "
				+ getDataType()
				+ ", value = "
				+ mValue.toString()
				+ "}";
	}

	@Override
	public int getLength() {
		return mValue.length;
	}

	@Override
	public String getFieldName() {
		return "[StaticBytes]";
	}

	@Override
	public Address getAddress() {
		return mAddress;
	}

	@Override
	public boolean isDefined() {
		return true;
	}
}
