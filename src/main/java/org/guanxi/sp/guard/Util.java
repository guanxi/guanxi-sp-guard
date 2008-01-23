/* CVS Header
   $
   $
*/

package org.guanxi.sp.guard;

public class Util {
  /**
   * Determines whether an Engine is using HTTPS for any of it's endpoints
   *
   * @param engineWAYFLocationService URL of Engine's WAFLocation service
   * @return true if the Engine is using HTTPS for any of it's endpoints otherwise false
   */
  public static boolean isEngineSecure(String engineWAYFLocationService) {
    return engineWAYFLocationService.toLowerCase().startsWith("https");
  }
}
