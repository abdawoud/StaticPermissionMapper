package cispa.permission.mapper.analysis;

import cispa.permission.mapper.utils.Constants;
import cispa.permission.mapper.utils.Helper;
import cispa.permission.mapper.utils.IOHelper;

public class ApiFileMapping {

	public ApiFileMapping() {}
	
	public void execute() {
		// This is naive approach to optimize the search within those files!
		Helper.runScript(IOHelper.getPathTo(Constants.SERVICE_MAPPING_FILE), Constants.OUTPUT);
	}
}
