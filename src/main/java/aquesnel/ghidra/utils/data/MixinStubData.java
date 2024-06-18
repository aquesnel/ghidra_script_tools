package aquesnel.ghidra.utils.data;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeDisplayOptions;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Saveable;
import ghidra.util.exception.NoValueException;

public interface MixinStubData extends Data {

	@Override
	public default Class<?> getValueClass() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean hasStringValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isConstant() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isVolatile() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isDefined() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Reference[] getValueReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void addValueReference(Address refAddr, RefType type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void removeValueReference(Address refAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isPointer() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isUnion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isStructure() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isArray() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isDynamic() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Data getComponent(int[] componentPath) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Data getComponentAt(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Data getComponentContaining(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default List<Data> getComponentsContaining(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Data getPrimitiveAt(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getComponentLevel() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getDefaultValueRepresentation() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getDefaultLabelPrefix(DataTypeDisplayOptions options) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getAddressString(boolean showBlockName, boolean pad) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getLabel() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Symbol[] getSymbols() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Symbol getPrimarySymbol() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Address getMinAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Address getMaxAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getMnemonicString() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String[] getCommentAsArray(int commentType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setComment(int commentType, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setCommentAsArray(int commentType, String[] comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void getBytesInCodeUnit(byte[] buffer, int bufferOffset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean contains(Address testAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int compareTo(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void addMnemonicReference(Address refAddr, RefType refType, SourceType sourceType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void removeMnemonicReference(Address refAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Reference[] getMnemonicReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Reference[] getOperandReferences(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Reference getPrimaryReference(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void addOperandReference(int index, Address refAddr, RefType type, SourceType sourceType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void removeOperandReference(int index, Address refAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Reference[] getReferencesFrom() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default ReferenceIterator getReferenceIteratorTo() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default ExternalReference getExternalReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void removeExternalReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setPrimaryMemoryReference(Reference ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setStackReference(int opIndex, int offset, SourceType sourceType, RefType refType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setRegisterReference(int opIndex, Register reg, SourceType sourceType, RefType refType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getNumOperands() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Address getAddress(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Scalar getScalar(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default short getShort(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getInt(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default long getLong(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default BigInteger getBigInteger(int offset, int size, boolean signed) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default <T extends Saveable> void setProperty(String name, T value) throws IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setProperty(String name, String value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setProperty(String name, int value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void setProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Saveable getObjectProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getStringProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getIntProperty(String name) throws NoValueException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean hasProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean getVoidProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Iterator<String> propertyNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default void removeProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getComment(int commentType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public default byte[] getBytes() throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Address getAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default boolean isBigEndian() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getFieldName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getPathName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default String getComponentPathName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default Data getRoot() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getRootOffset() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getParentOffset() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int[] getComponentPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public default int getComponentIndex() {
		throw new UnsupportedOperationException();
	}
}
