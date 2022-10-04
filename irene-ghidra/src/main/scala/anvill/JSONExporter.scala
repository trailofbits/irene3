/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package anvill;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util._;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Program
import java.io.FileOutputStream
import scalapb.json4s.JsonFormat

import scala.throws

/** TODO: Provide class-level documentation that describes what this exporter
  * does.
  */
class JSONExporter extends Exporter("Anvill JSON spec", "json", null) {

  @throws[IOException]()
  override def `export`(
      file: File,
      domainObj: DomainObject,
      addrSet: AddressSetView,
      monitor: TaskMonitor
  ): Boolean = {
    val os = new FileOutputStream(file)
    val spec = ProgramSpecifier.specifyProgram(domainObj.asInstanceOf[Program])
    val json: String = JsonFormat.toJsonString(spec)
    os.write(json.getBytes())
    true
  }

  override def getOptions(
      domainObjectService: DomainObjectService
  ): List[Option] = {
    var list: List[Option] = new ArrayList();
    list
  }

  @throws(classOf[OptionException])
  override def setOptions(
      options: List[Option]
  ): Unit = {}
}
