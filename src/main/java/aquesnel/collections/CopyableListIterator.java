package aquesnel.collections;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;

public class CopyableListIterator<T> implements ListIterator<T> {

	private final ArrayList<T> mList;
	private int mNextIndex;

	public CopyableListIterator(List<T> list) {
		this(new ArrayList<>(list), 0);
	}
	
	public CopyableListIterator(ArrayList<T> list) {
		this(list, 0);
	}
	
	public CopyableListIterator(ArrayList<T> list, int nextIndex) {
		mList = Objects.requireNonNull(list);
		mNextIndex = nextIndex;
		
		if (mNextIndex < 0 || mList.size() < mNextIndex) {
			throw new IllegalArgumentException(
					"Invalid value for nextIndex. Expected between 0 and "
					+ Integer.toString(mList.size())
					+ " Got: " 
					+ Integer.toString(mNextIndex));
			
		}
	}
	
	public CopyableListIterator<T> copyTo() {
		return new CopyableListIterator<>(mList, mNextIndex);
	}

	public void copyFrom(CopyableListIterator<T> source) {
		if (source.mList != this.mList) {
			throw new IllegalArgumentException(
					"Copying list iterator position from another list is not allowed. Expected: "
					+ System.identityHashCode(this.mList)
					+ " Got: "
					+ System.identityHashCode(source.mList));
		}
		this.mNextIndex = source.mNextIndex;
	}

	@Override
	public boolean hasNext() {
		return mNextIndex < mList.size();
	}

	@Override
	public T next() {
		T result = mList.get(mNextIndex);
		mNextIndex++;
		return result;
	}

	@Override
	public boolean hasPrevious() {
		return 1 < mNextIndex && mNextIndex <= mList.size();
	}

	@Override
	public T previous() {
		T result = mList.get(mNextIndex - 1);
		mNextIndex--;
		return result;
	}

	@Override
	public int nextIndex() {
		return mNextIndex;
	}

	@Override
	public int previousIndex() {
		return mNextIndex - 1;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void set(T e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void add(T e) {
		throw new UnsupportedOperationException();
	}

}
