import com.urbancode.air.AirPluginTool
import com.urbancode.air.Venafi.VenafiHelper

VenafiHelper helper = new VenafiHelper(new AirPluginTool(this.args[0], this.args[1]))

helper.authenticate()
