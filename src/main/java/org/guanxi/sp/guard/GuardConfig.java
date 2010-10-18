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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 * Config encapsulation
 *
 * @author alistair
 */
public class GuardConfig {
  private Properties config = null;

  /**
   * Loads the Guard config file
   *
   * @param configFilePath Full path/name of the config file
   */
  public GuardConfig(String configFilePath) {
    try {
      config = new Properties();
      config.load(new FileInputStream(configFilePath));
    }
    catch (FileNotFoundException fnfe) {
    }
    catch (IOException ioe) {
    }
  }

  /**
   * Retrieves a config option
   *
   * @param option the name of the option
   * @return the value for the option or null if it doesn't exist
   */
  public String get(String option) {
    return config.getProperty(option);
  }
}
