import io.shiftleft.codepropertygraph.generated.nodes.Method
import java.io.PrintWriter
import scala.collection.mutable
import scala.sys.process.*

case class Frame(depth: Int, method: Method)

@main def exec(inputProject: String, query: String, outFile: String) = {
  open(inputProject)

  val qSeen = mutable.Set[String]()
  val qBacktrace = mutable.Stack[Frame]()
  val qMethods = mutable.Stack[Frame]().addAll(cpg.method.name(query).map(m => Frame(0, m)))
  while (qMethods.nonEmpty) {
    val calleeFrame = qMethods.pop()
    while (qBacktrace.nonEmpty && qBacktrace.top.depth >= calleeFrame.depth) {
      qBacktrace.pop()
    }

    qBacktrace.push(calleeFrame)
    qSeen.add(calleeFrame.method.fullName)

    val callers = calleeFrame.method.caller.filter(m => !qSeen.contains(m.fullName)).l
    if (callers.isEmpty) {
      println(qBacktrace.map(_.method.fullName).mkString("\n"))
      println("---")

      qBacktrace.pop()
    } else {
      qMethods.pushAll(callers.map(m => Frame(calleeFrame.depth + 1, m)))
    }
  }
}
