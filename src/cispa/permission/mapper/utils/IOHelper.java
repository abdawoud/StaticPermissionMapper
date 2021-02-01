package cispa.permission.mapper.utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Arrays;

public class IOHelper {

	public static File[] getDexFilePaths(String[] only, String[] except) throws IOException {
		File dir = new File(Constants.DEXES_FOLDER);
		File[] files = dir.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				// @TODO FixMe
				// Problematic jar/dex files which cause an internal soot exception which I cannot resolve!
				if (Constants.EXCLUDED_JARS.contains(name))
					return false;

				if (only.length > 0)
					return Arrays.asList(only).contains(name);
				else if (except.length > 0)
					return !Arrays.asList(except).contains(name);
				else
					return true;//name.contains("Tethering.apk.dex");
			}
		});
		
		return files;
	}
	
	public static String getPathTo(String fileName) {
		File directory = new File(Constants.OUTPUT);
	    if (!directory.exists()){
	        directory.mkdir();
	    }
		return Constants.OUTPUT + "/" + fileName;
	}
	
	public static BufferedWriter getWriter(String fileName, boolean append) throws IOException {
		String path = getPathTo(fileName);
		FileWriter fileWritter = new FileWriter(path, append);
		return new BufferedWriter(fileWritter);
	}
	
	public static BufferedReader getReader(String fileName) throws IOException {
		String path = getPathTo(fileName);
		return new BufferedReader(new FileReader(path));
	}
	
	public static FileReader getFileReader(String fileName) throws FileNotFoundException {
		String path = getPathTo(fileName);
		return new FileReader(path);
	}
}
