// prepend comment to each INT
//@author sam_
//@category DOS
//@keybinding 
//@menupath 
//@toolbar 

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.base.Objects;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class LabelInterrupts extends GhidraScript {

    public void run() throws Exception {
    	Map<Integer, List<Map<String, Object>>> infos = new HashMap<>();
    	String WS0 = "\\s*", WS1 = "\\s+", QUOT0 = "\"?", NL = "\\r?\\n+", a = "<a" + WS1 + "href" + WS0 + "=" + WS0 + QUOT0 + "([^>\"]+)" + QUOT0 + WS0 + ">";
    	String b = "<b>" + WS0 + "Int" + WS1 + "[0-9A-F]+(/[^<]+h)" + WS0 + "</b>";
    	Matcher m = Pattern.compile(a + WS0 + b + WS0 + "</a>" + WS0 + NL + WS0 + "-" + WS1 + "([^<]+)" + WS0 + "<br>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher("");
    	for (Instruction i = getFirstInstruction(); i != null; i = i.getNext()) {
    		if (i.getMnemonicString().equalsIgnoreCase("INT")) {
    			labelInterrupt(infos, m, i);
    		}
    	}
    }

    private void labelInterrupt(Map<Integer, List<Map<String, Object>>> infos, Matcher m, Instruction i) throws IOException {
    	Scalar s = i.getScalar(0);
		Integer code = Integer.decode(s.toString());
		List<Map<String, Object>> hits = new ArrayList<>(Collections.nCopies(5, null));	// no match + 4 general registers
		for (Map<String, Object> regValues : getExpectedRegisterValues(infos, m, code)) {
			boolean hit = regValues.entrySet().stream().skip(1).allMatch(e -> {
				Register register = i.getRegister(e.getKey());
				RegisterValue expected = new RegisterValue(register, BigInteger.valueOf((Integer) e.getValue()));
				RegisterValue actual = i.getRegisterValue(register);
				if (actual == null && register.getParentRegister() != null) {
					actual = i.getRegisterValue(register.getParentRegister());
				}
				if (actual == null) {
					actual = backtrackToValue(register, i.getPrevious(), 10);
				}
				return expected.equals(actual);
			});
			if (hit) {
				Map<String, Object> otherValues = hits.set(regValues.size() - 1, regValues);
				if (otherValues != null) {	// should not happen, or there should be even longer hit
//					println(otherValues + " replaced with " + regValues);
				}
			}
		}
		if (hits.removeAll(Collections.singleton(null)) && hits.isEmpty()) {
			println(i.getAddress() + " " + i + " left without comment");
		} else {
			Map.Entry<String, Object> entry = hits.iterator().next().entrySet().iterator().next();
			i.setComment(CodeUnit.PRE_COMMENT, entry.getKey() + " {@url " + entry.getValue() + "}");
		}
    }
    
    private RegisterValue backtrackToValue(Register register, Instruction i, int limit) {
		for (int j = 0; i != null && j < limit; j++, i = i.getPrevious()) {
			if (i.hasValue(register)) {
				return i.getRegisterValue(register);
			} else if (register.getParentRegister() != null && i.hasValue(register.getParentRegister())) {
				return i.getRegisterValue(register.getParentRegister());
			} else if (!"MOV".equalsIgnoreCase(i.getMnemonicString())) {
				continue;
			}
			try {
				if (register.equals(i.getRegister(0))) {
					return new RegisterValue(register, BigInteger.valueOf(Integer.decode(String.valueOf(i.getScalar(1)))));
				} else if (i.getRegister(0) != null && register.equals(i.getRegister(0).getParentRegister())) {
					return new RegisterValue(register, BigInteger.valueOf(Integer.decode(String.valueOf(i.getScalar(1)))));
				} else if (register.getParentRegister() != null && register.getParentRegister().equals(i.getRegister(0))) {
					return new RegisterValue(register, BigInteger.valueOf(Integer.decode(String.valueOf(i.getScalar(1)))));
				}
			} catch (NumberFormatException notScalar) {}
		}
		return null;
    }
    
    private List<Map<String, Object>> getExpectedRegisterValues(Map<Integer, List<Map<String, Object>>> infos, Matcher m, Integer code) throws IOException {
    	List<Map<String, Object>> info = infos.get(code);
		if (info == null) {
			info = new ArrayList<>();
			String url = String.format("http://www.ctyme.com/intr/int-%02X.htm", code);
			String html = html(url);
//			println("got " + html.length() + " bytes");
			for (m.reset(html); m.find(); ) {	// Jsoup would be better fit...
	    		url = m.group(1);
	    		String[] pairs = m.group(2).split("[/=h]+");	// /REG=VALh
	    		String desc = m.group(3);
	    		Map<String, Object> regValues = new LinkedHashMap<>(1 + pairs.length / 2);
	    		regValues.put(desc, url);
	    		for (int j = 1; j < pairs.length; j+=2) {	// starting from 1 as leading separator '/' produces empty string at index 0
	    			regValues.put(pairs[j], Integer.decode("0x" + pairs[j + 1]));
				}
	    		info.add(regValues);
	    	}
//			println("matched " + (info.size() - 1) + " patterns");
			infos.put(code, info);
		}
		return info;
    }

    private String html(String url) throws IOException {
    	try (InputStream in = new FileInputStream(url.replaceAll(".*/", "bin/"))) {
    		println("loading from " + url.replaceAll(".*/", "bin/"));
    		return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    	} catch (FileNotFoundException bummer) {
    		URL u = new URL(url);
        	println("downloading from " + url);
        	try (InputStream in = u.openStream()) {
        	    return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        	}
    	}
    }
}
