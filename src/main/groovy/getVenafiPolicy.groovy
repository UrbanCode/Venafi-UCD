import com.urbancode.air.Venafi.VenafiHelper
import com.urbancode.air.plugin.helper.NewAirPluginTool

VenafiHelper helper = new VenafiHelper(new NewAirPluginTool(this.args[0], this.args[1]))

helper.getVenafiPolicy()
