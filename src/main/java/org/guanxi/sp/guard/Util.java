//: "The contents of this file are subject to the Mozilla Public License
//: Version 1.1 (the "License"); you may not use this file except in
//: compliance with the License. You may obtain a copy of the License at
//: http://www.mozilla.org/MPL/
//:
//: Software distributed under the License is distributed on an "AS IS"
//: basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//: License for the specific language governing rights and limitations
//: under the License.
//:
//: The Original Code is Guanxi (http://www.guanxi.uhi.ac.uk).
//:
//: The Initial Developer of the Original Code is Alistair Young alistair@codebrane.com
//: All Rights Reserved.
//:

package org.guanxi.sp.guard;

import java.util.ResourceBundle;

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

  /**
   * Loads the Guard config file
   *
   * @return ResourceBundle representing the Guard configuration
   */
  public static ResourceBundle getConfig() {
    return ResourceBundle.getBundle("guanxi-sp-guard");
  }
}
