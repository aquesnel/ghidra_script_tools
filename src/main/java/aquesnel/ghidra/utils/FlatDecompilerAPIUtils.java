package aquesnel.ghidra.utils;

import java.lang.ref.SoftReference;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import aquesnel.ghidra.utils.data.DataUtils;

import java.util.Optional;

import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;

public final class FlatDecompilerAPIUtils {
//	private DecompInterface decomplib;
//	private DecompileResults lastResults = null;
//	
//	// Decompiler stuff - cache some information about the last decompilation
//	private HighFunction hfunction = null;
//
//	private Address lastDecompiledFuncAddr = null;
	
	public static Optional<Data> readLocalVariable(GhidraScript script, String variableName)
	{
		Optional<HighFunction> hfOpt = getHighFunction(script);

		if (hfOpt.isEmpty()) {
			return Optional.empty();
		}
		HighFunction hf = hfOpt.get();
		
		// try to map the variable
//		highVar = hf.getMappedSymbol(storageAddress, f.getEntryPoint().subtractWrap(1L));
		HighSymbol highSymbol = hf.getLocalSymbolMap().getNameToSymbolMap().get(variableName);
//		script.println("Decompile Input, high symbol: " + Objects.toString(highSymbol));
		if (highSymbol == null) {
			return Optional.empty();
		}
		HighVariable highVar = highSymbol.getHighVariable();
//		script.println("Decompile Input, high variable: " + Objects.toString(highVar));
		return readVariable(script, highVar);
	}

	public static Optional<Data> readVariable(GhidraScript script, HighVariable highVar) {
		if (highVar == null) {
			return Optional.empty();
		}
		Varnode var = highVar.getRepresentative();
//		script.println("Decompile Input highVar: " + Objects.toString(highVar) + " -> varnode: " + Objects.toString(var));
		if (var == null) {
			return Optional.empty();
		}
		
//		FlatDebuggerAPI debugger = FlatDebuggerAPIUtils.fromScript(script);
//		final Data data;
//		//read storage location
//		if (var.isRegister())
//		{
//			Register reg = script.getCurrentProgram().getLanguage().getRegister(var.getAddress(), var.getSize());
//			data = new RegisterData(
//					debugger.readRegister(reg), 
//					highVar.getDataType(), 
//					script.getCurrentProgram());
//		}
//		else if (var.isUnique()) {
//			data = new BytesData(
//					new byte[0], 
//					false,
//					var.getAddress(),
//					highVar.getDataType(), 
//					script.getCurrentProgram());
//		}
//		else  {
////			FlatDebuggerAPI debugger = FlatDebuggerAPIUtils.fromScript(script);
////			byte[] bytes = debugger.readMemory(var.getAddress(), highVar.getDataType().getLength(), script.getMonitor());
////			data = script.getDataAt();
//			data = new MemoryData(
//					var.getAddress(), 
//					highVar.getDataType(), 
//					script.getCurrentProgram(),
//					script);
////					debugger.getCurrentRecorder().getTrace().getProgramView());
//			
//		}
////		script.println("Decompile Input, data: " + Objects.toString(data));
//		return Optional.ofNullable(data);
		return Optional.ofNullable(DataUtils.asData(script, var.getAddress(), highVar.getDataType()));
	}

	public static Map<String, HighVariable>  getLocalVariables(GhidraScript script)
	{
		Optional<HighFunction> hfOpt = getHighFunction(script);
		if (hfOpt.isEmpty()) {
			return Collections.emptyMap();
		}
		Map<String, HighVariable> result = new HashMap<>();
		for (Entry<String, HighSymbol> entry : hfOpt.get()
				.getLocalSymbolMap()
				.getNameToSymbolMap()
				.entrySet())
		{
			HighVariable hv = entry.getValue().getHighVariable();
			if (hv != null) {
				result.put(entry.getKey(), hv);
			}
		}
		return result;
	}
	
	private static ThreadLocal<SoftReference<Map<Address, DecompileResults>>> LOCAL_CACHE = ThreadLocal.withInitial(() -> new SoftReference<>(new HashMap<>()));
	private static Optional<HighFunction> getHighFunction(GhidraScript script) {
		
		FlatDebuggerAPI debugger = FlatDebuggerAPIUtils.fromScript(script);
		DecompInterface decomplib =
				setUpDecompiler(script, script.getState(), script.getCurrentProgram());
		
		Address pc = debugger.getProgramCounter();
		Address staticPc = debugger.translateDynamicToStatic(pc);
//		script.println("Decompile Input, variable name: " + variableName);
//		script.println("Decompile Input, pc dynamic address: " + pc);
//		script.println("Decompile Input, pc static  address: " + staticPc);
		
		// I'm pretty sure decompiling is expensive, so cache the results
		// my manual test says that this is MUCH faster than not caching
		Map<Address, DecompileResults> cache = LOCAL_CACHE.get().get();
		if (cache == null) {
			cache = new HashMap<>();
			LOCAL_CACHE.set(new SoftReference<>(cache));
		}
		DecompileResults results = cache.get(staticPc);
		if (results == null) {
			Function func = script.getFunctionContaining(staticPc);//script.getCurrentProgram().getFunctionManager().getFunctionContaining(staticPc);
	//		Address funcEntry = func.getEntryPoint();
	//		script.println("Decompile Input, func: " + func);
	//		script.println("Decompile Input, funcEntry: " + funcEntry);
			
			results = decompileFunction(func, decomplib, script.getMonitor());
			cache.put(staticPc, results);
		}

		HighFunction hf = results.getHighFunction();
//		script.println("Decompile Input, high func: " + Objects.toString(hf));
		if (hf == null) {
			return Optional.empty();
		}
		return Optional.of(hf);
	}
	
//	private Function getReferencedFunction(Program currentProgram, Address functionAddress) {
//		Function f = currentProgram.getFunctionManager().getFunctionAt(functionAddress);
//		// couldn't find the function, see if there is an external ref there.
//		if (f == null) {
//			Reference[] referencesFrom =
//				currentProgram.getReferenceManager().getReferencesFrom(functionAddress);
//			for (Reference reference : referencesFrom) {
//				if (reference.isExternalReference()) {
//					functionAddress = reference.getToAddress();
//					f = currentProgram.getFunctionManager().getFunctionAt(functionAddress);
//					if (f != null) {
//						break;
//					}
//				}
//			}
//		}
//		return f;
//	}
	
	/**
	 * Try to locate the Varnode that represents the variable in the listing or
	 * decompiler. In the decompiler this could be a local/parameter at any
	 * point in the decompiler. In the listing, it must be a parameter variable.
	 * 
	 * @return the varnode
	 */
//	private Varnode getVarnodeLocation(GhidraScript script, Program currentProgram, ProgramLocation currentLocation, TaskMonitor monitor) {
//		Varnode var = null;
//
//		if (currentLocation instanceof DecompilerLocation) {
//			DecompilerLocation dloc;
//
//			// get the Varnode under the cursor
//			dloc = (DecompilerLocation) currentLocation;
//			ClangToken tokenAtCursor = dloc.getToken();
//			var = DecompilerUtils.getVarnodeRef(tokenAtCursor);
//			// fixupParams(dloc.getDecompile(), currentLocation.getAddress());
//			if (tokenAtCursor == null) {
//				script.println("****   please put the cursor on a variable in the decompiler!");
//				return null;
//			}
////			lastResults = dloc.getDecompile();
//		}
//		else {
//			// if we don't have one, make one, and map variable to a varnode
//			HighSymbol highVar = computeVariableLocation(currentProgram, currentLocation, monitor);
//			if (highVar != null) {
//				var = highVar.getHighVariable().getRepresentative();
//			}
//			else {
//				return null;
//			}
//		}
//		return var;
//	}
	
//	private HighSymbol computeVariableLocation(Program currProgram, ProgramLocation location, TaskMonitor monitor) {
//		HighSymbol highVar = null;
//		Address storageAddress = null;
//
//		// make sure what we are over can be mapped to decompiler
//		// param, local, etc...
//
//		if (location instanceof VariableLocation) {
//			VariableLocation varLoc = (VariableLocation) location;
//			storageAddress = varLoc.getVariable().getMinAddress();
//		}
//		else if (location instanceof FunctionParameterFieldLocation) {
//			FunctionParameterFieldLocation funcPFL = (FunctionParameterFieldLocation) location;
//			storageAddress = funcPFL.getParameter().getMinAddress();
//		}
//		else if (location instanceof OperandFieldLocation) {
//			OperandFieldLocation opLoc = (OperandFieldLocation) location;
//			int opindex = opLoc.getOperandIndex();
//			if (opindex >= 0) {
//				Instruction instr = currProgram.getListing().getInstructionAt(opLoc.getAddress());
//				if (instr != null) {
//					Register reg = instr.getRegister(opindex);
//					if (reg != null) {
//						storageAddress = reg.getAddress();
//					}
//				}
//			}
//		}
//
//		if (storageAddress == null) {
//			return null;
//		}
//
//		Address addr = location.getAddress();
//		if (addr == null) {
//			return null;
//		}
//
//		Function f = currProgram.getFunctionManager().getFunctionContaining(addr);
//		if (f == null) {
//			return null;
//		}
//
////		DecompileResults results = decompileFunction(f, decomplib, monitor);
////
////		HighFunction hf = results.getHighFunction();
////		if (hf == null) {
////			return null;
////		}
////
////		// try to map the variable
////		highVar = hf.getMappedSymbol(storageAddress, f.getEntryPoint().subtractWrap(1L));
////		if (highVar == null) {
////			highVar = hf.getMappedSymbol(storageAddress, null);
////		}
////		if (highVar == null) {
////			highVar = hf.getMappedSymbol(storageAddress, f.getEntryPoint());
////		}
////
////		if (highVar != null) {
////			// fixupParams(results, location.getAddress());
////		}
//
//		return highVar;
//	}

	private static DecompInterface setUpDecompiler(GhidraScript script, GhidraState state, Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(program)) {
			script.println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public static DecompileResults decompileFunction(Function f, DecompInterface decompInterface, TaskMonitor monitor) {
		DecompileResults lastResults;
		// don't decompile the function again if it was the same as the last one
		//
//		if (!f.getEntryPoint().equals(lastDecompiledFuncAddr)) {
			lastResults = decompInterface.decompileFunction(f,
				decompInterface.getOptions().getDefaultTimeout(), monitor);
//		}

//		hfunction = lastResults.getHighFunction();
//
//		lastDecompiledFuncAddr = f.getEntryPoint();

		return lastResults;
	}
	
//	private static DecompInterface setUpDecompiler(GhidraScript script, GhidraState state, Program currentProgram) {
//		DecompInterface decompInterface = new DecompInterface();
//	
//		// call it to get results
//		if (!decompInterface.openProgram(currentProgram)) {
//			script.println("Decompile Error: " + decompInterface.getLastMessage());
//			return null;
//		}
//	
//		DecompileOptions options;
//		options = new DecompileOptions();
//		OptionsService service = state.getTool().getService(OptionsService.class);
//		if (service != null) {
//			ToolOptions opt = service.getOptions("Decompiler");
//			options.grabFromToolAndProgram(null, opt, currentProgram);
//		}
//		decompInterface.setOptions(options);
//	
//		decompInterface.toggleCCode(true);
//		decompInterface.toggleSyntaxTree(true);
//		decompInterface.setSimplificationStyle("decompile");
//	
//		return decompInterface;
//	}
	
//	private static DecompileResults decompileFunction(Function f, DecompInterface decompInterface, TaskMonitor monitor) {
//		DecompileResults lastResults;
//		// don't decompile the function again if it was the same as the last one
//		//
////		if (!f.getEntryPoint().equals(lastDecompiledFuncAddr)) {
//			lastResults = 
//					decompInterface.decompileFunction(f,
//				decompInterface.getOptions().getDefaultTimeout(), monitor);
////		}
//	
////		hfunction = lastResults.getHighFunction();
////	
////		lastDecompiledFuncAddr = f.getEntryPoint();
//	
//		return lastResults;
//	}
}
