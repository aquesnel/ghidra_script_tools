package aquesnel.ghidra.utils.data;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.listing.Data;

public class DataStructBackedMap implements Map<String, Object>{
	
	private final Map<String, Integer> mComponantIndexByFieldName;
	private final Data mBackingData;
	
	public DataStructBackedMap(Data data) {
		mBackingData = Objects.requireNonNull(data, "data must not be null");
		
		Map<String, Integer> temp = new LinkedHashMap<>();
		for (int i = 0; i < mBackingData.getNumComponents(); i++)
		{
			temp.put(mBackingData.getComponent(i).getFieldName(), i);
		}
		mComponantIndexByFieldName = Collections.unmodifiableMap(temp);
	}

	@Override
	public int size() {
		return mBackingData.getNumComponents();
	}

	@Override
	public boolean isEmpty() {
		return size() == 0;
	}

	@Override
	public Object get(Object key) {
		return DataUtils.getValue(mBackingData.getComponent(mComponantIndexByFieldName.get(key)));
	}

	@Override
	public boolean containsKey(Object key) {
		return mComponantIndexByFieldName.containsKey(key);
	}

	@Override
	public Set<String> keySet() {
		return mComponantIndexByFieldName.keySet();
	}

	@Override
	public Collection<Object> values() {
		ArrayList<Object> result = new ArrayList<>(size());
		for (String key: keySet()) {
			result.add(get(key));
		}
		return result;
	}

	@Override
	public Set<Entry<String, Object>> entrySet() {
		Set<Entry<String, Object>> result = new LinkedHashSet<>(size());
		for (final String key: keySet()) {
			result.add(new Map.Entry<>() {

				@Override
				public String getKey() {
					return key;
				}

				@Override
				public Object getValue() {
					return get(key);
				}

				@Override
				public Object setValue(Object value) {
					throw new UnsupportedOperationException();
				}
				
			});
		}
		return result;
	}
	
	public String toString() {
		return new LinkedHashMap<>(this).toString();
	}
	
	/*
	 * Unsupported Map APIs
	 */

	@Override
	public boolean containsValue(Object value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object put(String key, Object value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object remove(Object key) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void putAll(Map<? extends String, ? extends Object> m) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}
}
