package aquesnel.ghidra.utils.data;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import aquesnel.ghidra.utils.FlatDebuggerAPIUtils;
import ghidra.app.script.GhidraScript;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

public final class DataUtils {

	public static Data asData(GhidraScript script, Address addr, DataType datatype) {
		FlatDebuggerAPI debugger = FlatDebuggerAPIUtils.fromScript(script);
		final Data data;
		//read storage location
		if (addr.isRegisterAddress())
		{
			Register reg = script.getCurrentProgram().getLanguage().getRegister(addr, datatype.getLength());
			data = new RegisterData(
					debugger.readRegister(reg), 
					datatype, 
					script.getCurrentProgram());
		}
		else if (addr.isUniqueAddress()) {
			data = new BytesData(
					new byte[0], 
					false,
					addr,
					datatype, 
					script.getCurrentProgram());
		}
		else if (addr.isMemoryAddress() || addr.isStackAddress()) {
			data = new MemoryData(
					addr, 
					datatype, 
					script.getCurrentProgram(),
					script);
		}
		else {
			throw new UnsupportedOperationException("Address type is not supported. Got: " + addr.toString());
		}
		return data;
	}
	
	public static Data asConstantData(String data, Program program) {
		return new BytesData(
				data.getBytes(StandardCharsets.UTF_8),
				false,
				StringUTF8DataType.dataType,
				program);
	}
	
	public static Data getPointerToData(Data data) {

		DataType referredDataType = data.getBaseDataType();
		if (referredDataType instanceof Array arrayDataType) {
			// when dereferencing an array, the change the datatype to the array's element data type
			referredDataType = arrayDataType.getDataType();
		}
		
		return new BytesData(
				data.getAddress().getOffsetAsBigInteger().toByteArray(),
				true, // BigInteger.toByteArray() returns data as Big endian
				new PointerDataType(referredDataType, data.getProgram().getDataTypeManager()),
				data.getProgram());
	}
	
	public static Object getValue(Data data) {
		if (data.getBaseDataType() instanceof Structure) {
			return new DataStructBackedMap(data);
		}
		if (data.getBaseDataType() instanceof Array dataArray) {
			return new DataArrayBackedList<>(data);
//			if (ArrayStringable.getArrayStringable(dataArray.getDataType()) == null) {
//				return new DataArrayBackedList<>(data);
//			}
			// else fall through and get the array interpreted as a c-string
		}
		
		MemBuffer buf;
		try {
			buf = new ByteMemBufferImpl(data.getAddress(), data.getBytes(), data.isBigEndian());
		} catch (MemoryAccessException e) {
			throw new RuntimeException(e);
		}
		
		if (data.getBaseDataType() instanceof PointerDataType) {
			
			return PointerDataType.getAddressValue(
					buf, 
					data.getLength(), 
					data.getProgram().getAddressFactory().getAddressSpace("ram"));
		}
//		if(data.getBaseDataType() instanceof AbstractIntegerDataType intDataType) {
//			long longValue = intDataType.isSigned() 
//					? mRegisterValue.getSignedValue().longValue() 
//					: mRegisterValue.getUnsignedValue().longValue();
//			
//			return new Scalar(
//					mRegisterValue.getRegister().getBitLength(), 
//					longValue, 
//					intDataType.isSigned());
//		}
		
		Object result = data.getDataType().getValue(buf, data, data.getLength());
		if (result instanceof Scalar s) {
			return s.getValue();
		}
		return result;
	}
	
	public static String toDebugInfo(Data data) {
		
		if (data == null) {
			return "[null]";
		}
		
		return 
				"Field: "
				+ Objects.toString(data.getFieldName(), "[root]")
				+ "\n | Data class: " 
				+ data.getClass().getName()
				+ "\n | NumComponants: "
				+ Integer.toString(data.getNumComponents())
				+ "\n | Length: "
				+ Integer.toString(data.getLength())
				+ "\n | DataType: " 
				+ data.getBaseDataType()
				+ "\n | DataType class: " 
				+ data.getBaseDataType().getClass().getName()
				+ "\n | DataType NumComponants: "
				+ Integer.toString(data.getDataType().getLength())
				+ "\n | Value: " 
				+ Objects.toString(DataUtils.getValue(data));
	}
	
	private static final Pattern PRINTABLE_CHARS = Pattern.compile("\\p{Print}");
	@SuppressWarnings("unchecked")
	public static String toString(Object data) {
		
		if (data == null) {
			return "[null]";
		}
		
		Object value = data;
		if (data instanceof Data dataValue) {
			value = getValue(dataValue);
		}
		
		if (value instanceof List<?> listValue) {
			ArrayList<Object> array = new ArrayList<>(listValue.size());
			for (Object item: listValue) {
				array.add(toString(item));
			}
			return array.toString();
		}
		else if (value instanceof Map mapValue) {
			Map<String, Object> map = new LinkedHashMap<>();
			for (Map.Entry<String, Object> entry: ((Map<String, Object>) mapValue).entrySet()) {
				map.put(entry.getKey(), toString(entry.getValue()));
			}
			return map.toString();
		}
		else if (value instanceof Character c) {
			StringBuilder sb = new StringBuilder();
			if (PRINTABLE_CHARS.matcher(CharBuffer.wrap(new char[] {c})).matches()) {
				sb.append(c);
			}
			else {
				sb.append("?");
			}
			sb.append(" (0x");
			sb.append(Integer.toHexString(Character.codePointAt(new char[] {c}, 0)));
			sb.append(")");
			return sb.toString();
		}
		return Objects.toString(value);
	}
	
	public static Data getField(GhidraScript script, Data data, String fieldName) {
		if (data.getBaseDataType() instanceof Structure) {
			for (int i = 0; i < data.getNumComponents(); i++)
			{
				if (data.getComponent(i).getFieldName().equals(fieldName)) {
					return data.getComponent(i);
				}
			}
		}
		else if (data.getBaseDataType() instanceof Array) {
			int arrayIndex = Integer.parseInt(fieldName);
			return data.getComponent(arrayIndex);
		}
		else if (data.getBaseDataType() instanceof Pointer) {
			int arrayIndex = Integer.parseInt(fieldName);
			return new PointerSliceData(script, data, 0, arrayIndex + 1).getComponent(arrayIndex);
		}
		throw new IllegalArgumentException("Unknown field name: " + fieldName);
	}
	
	public static Data getArraySlice(Data data, int startIndexInclusive, int endIndexExclusive) {
		return new ArraySliceData(data, startIndexInclusive, endIndexExclusive);
	}
	
	public static Data getPointerSlice(GhidraScript script, Data data, int startIndexInclusive, int endIndexExclusive) {
		return new PointerSliceData(script, data, startIndexInclusive, endIndexExclusive);
	}
	
	public static Data getDataSlice(GhidraScript script, Data data, int startIndexInclusive, int endIndexExclusive) {
		if (data.getBaseDataType() instanceof Array) {
			return DataUtils.getArraySlice(
					data, 
					startIndexInclusive,
					endIndexExclusive);
		}
		else if (data.getBaseDataType() instanceof Pointer) {
			return DataUtils.getPointerSlice(
					script,
					data, 
					startIndexInclusive,
					endIndexExclusive);
		}
		else {
			throw new IllegalArgumentException("getDataSlice() only supports data type of 'Array' and 'Pointer'. Got: " + data.getBaseDataType());
		}
	}
	
	/**
	 * Copied from {@link ghidra.program.database.code.DataDB#getBaseDataType()}
	 */
	public static DataType getBaseDataType(Data data) {
		DataType dt = data.getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		return dt;
	}
//	
//	public static String getFieldName(Data data) {
//		
//		if (data instanceof RegisterData) {
//			return data.getFieldName();
//		}
//		
//		for (int i = 0; i < data.getNumComponents(); i++)
//		{
//			if (data.getComponent(i).getFieldName().equals(fieldName)) {
//				return data.getComponent(i);
//			}
//		}
//		throw new IllegalArgumentException("Unknown field name: " + fieldName);
//	}
}
