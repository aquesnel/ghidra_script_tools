package aquesnel.ghidra.utils;


import java.util.Collection;

import ghidra.app.script.GhidraScript;

public final class PrintUtils {
	public static <T> void printCollection(GhidraScript self, String name, Collection<T> collection) {
		printCollection(self, name, collection, Object::toString);
	}
	
	public static <T> void printCollection(GhidraScript self, String name, Collection<T> collection, java.util.function.Function<T, String> toString) {
		self.println(String.format("%s collection has size: %d and type %s", 
				name, 
				collection.size(), 
				collection.stream()
						.findFirst()
						.map(o -> o.getClass().getSimpleName())
						.orElse("Unknown")));
		for(T o : collection) {
			self.println("  " + toString.apply(o));
		}
	}
}
