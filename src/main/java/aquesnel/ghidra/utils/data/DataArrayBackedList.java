package aquesnel.ghidra.utils.data;




import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;
import java.util.Objects;



import ghidra.program.model.data.Array;
import ghidra.program.model.listing.Data;

public final class DataArrayBackedList<T> implements List<T> {

	private final Data mBackingData;
	private final int mStartIndexInclusive;
	private final int mEndIndexExclusive;
	
	public DataArrayBackedList(Data data) {
		this(data, getElementClass(data));
	}
	public DataArrayBackedList(Data data, Class<T> elementClazz) {
		this(data, elementClazz, 0, data.getNumComponents());
	}
	
	private DataArrayBackedList(Data data, Class<T> elementClazz, int startIndex, int endIndex) {
		mStartIndexInclusive = startIndex;
		mEndIndexExclusive = endIndex;
		mBackingData = Objects.requireNonNull(data, "data must not be null");
		
		if (mStartIndexInclusive < 0) {
			throw new IllegalArgumentException(
					"StartIndex must be greater than 0. StartIndex: " 
					+ Integer.toString(startIndex));
		}
		if (mBackingData.getNumComponents() < mEndIndexExclusive) {
			throw new IllegalArgumentException(
					"EndIndex must be less than or equal to the number of Componants. NumComponants: "
					+ Integer.toString(mBackingData.getNumComponents())
					+ " EndIndex: " 
					+ Integer.toString(mEndIndexExclusive));
		}
		if (mEndIndexExclusive < mStartIndexInclusive) {
			throw new IllegalArgumentException(
					"EndIndex must be greater than or equal to the number of Componants. StartIndex: "
					+ Integer.toString(mStartIndexInclusive)
					+ " EndIndex: " 
					+ Integer.toString(endIndex));
		}
		
		if (!(data.getDataType() instanceof Array)) {
			throw new IllegalArgumentException(
					"The DataType for `data` must implement `Array`. Found: " 
					+ data.getDataType().getClass().getName());
		}
		
		Objects.requireNonNull(elementClazz, "elementClazz must not be null");
		if (!elementClazz.equals(getElementClass(data))) {
			throw new IllegalArgumentException(
					"The Array's elements are not of the given type. Given: "
					+ elementClazz.getName()
					+ " Found: " 
					+ data.getDataType().getClass().getName());
		}
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked", "cast" })
	private static <U> Class<U> getElementClass(Data data) {
		return (Class<U>)(Class) data.getDataType().getValueClass(data);
	}
	
	private ArrayList<T> toArrayList() {
		ArrayList<T> array = new ArrayList<>(size());
		for (T item: this) {
			array.add(item);
		}
		return array;
	}

	/*
	 * Supported List APIs
	 */
	
	@SuppressWarnings("unchecked")
	@Override
	public T get(int index) {
		if (size() <= index) {
			throw new IllegalArgumentException(
					"Index must be smaller than the list size. Size(): "
							+ Integer.toString(size())
							+ " Index: " 
							+ Integer.toString(index));
		}
		return (T) DataUtils.getValue(mBackingData.getComponent(mStartIndexInclusive + index));
	}
	
	@Override
	public int size() {
		return mEndIndexExclusive - mStartIndexInclusive;
	}

	@Override
	public boolean isEmpty() {
		return size() == 0;
	}

	@Override
	public Iterator<T> iterator() {
		return new Iterator<T>() {

			private int mBeforeIndex = 0;
			
			@Override
			public boolean hasNext() {
				return mBeforeIndex < size();
			}

			@Override
			public T next() {
				if (!hasNext()) {
					throw new NoSuchElementException();
				}
				T result = get(mBeforeIndex);
				mBeforeIndex++;
				return result;
			}
		};
	}
	
	public String toString() {
		return toArrayList().toString();
	}

	@Override
	public Object[] toArray() {
		return toArrayList().toArray();
	}

	@SuppressWarnings("cast")
	@Override
	public <U> U[] toArray(U[] a) {
		return (U[]) toArrayList().toArray(a);
	}

	@Override
	public List<T> subList(int fromIndex, int toIndex) {
		if (size() < toIndex - fromIndex) {
			throw new IllegalArgumentException(
					"IndexRange must be less than or equal to the list size. Size(): "
							+ Integer.toString(size())
							+ " StartIndex: " 
							+ Integer.toString(fromIndex)
							+ " EndIndex: " 
							+ Integer.toString(toIndex));
		}
		if (fromIndex < 0) {
			throw new IllegalArgumentException(
					"StartIndex must be greater than 0. StartIndex: " 
					+ Integer.toString(fromIndex));
		}
		if (toIndex < 0) {
			throw new IllegalArgumentException(
					"EndIndex must be greater than 0. EndIndex: " 
					+ Integer.toString(toIndex));
		}
		
		return new DataArrayBackedList<>(
				mBackingData, 
				getElementClass(mBackingData), 
				mStartIndexInclusive + fromIndex, 
				mStartIndexInclusive + toIndex);
	}

	/*
	 * Unsupported List APIs
	 */
	
	@Override
	public ListIterator<T> listIterator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ListIterator<T> listIterator(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean add(T e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean contains(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean addAll(Collection<? extends T> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean addAll(int index, Collection<? extends T> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}

	@Override
	public T set(int index, T element) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void add(int index, T element) {
		throw new UnsupportedOperationException();
	}

	@Override
	public T remove(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int indexOf(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int lastIndexOf(Object o) {
		throw new UnsupportedOperationException();
	}
}
