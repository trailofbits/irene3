package anvill.plugin.anvillgraph.parser;

import anvill.plugin.anvillgraph.grammar.CLexer;
import anvill.plugin.anvillgraph.grammar.CParser;
import ghidra.util.Msg;
import java.io.IOException;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.Token;
import org.fife.io.DocumentReader;
import org.fife.ui.rsyntaxtextarea.RSyntaxDocument;
import org.fife.ui.rsyntaxtextarea.parser.AbstractParser;
import org.fife.ui.rsyntaxtextarea.parser.DefaultParseResult;
import org.fife.ui.rsyntaxtextarea.parser.DefaultParserNotice;
import org.fife.ui.rsyntaxtextarea.parser.ParseResult;

public class AntlrCParser extends AbstractParser {
  private class AntlrCErrorListener extends BaseErrorListener {
    private final DefaultParseResult result;

    public AntlrCErrorListener(DefaultParseResult result) {
      this.result = result;
    }

    @Override
    public void syntaxError(
        Recognizer<?, ?> recognizer,
        Object offendingSymbol,
        int line,
        int charPositionInLine,
        String msg,
        RecognitionException e) {
      Msg.info(
          getClass(),
          "line " + line + ":" + charPositionInLine + " at " + offendingSymbol + ": " + msg);
      var length = -1;
      var offset = -1;
      if (offendingSymbol instanceof Token) {
        var token = (Token) offendingSymbol;
        length = token.getStopIndex() - token.getStartIndex() + 1;
        offset = token.getStartIndex();
      } else {
        Msg.error(getClass(), "Unhandled token type: " + e);
      }
      var notice = new DefaultParserNotice(AntlrCParser.this, msg, line, offset, length);
      result.addNotice(notice);
    }
  }

  @Override
  public ParseResult parse(RSyntaxDocument doc, String style) {
    var reader = new DocumentReader(doc);
    try {
      CharStream input = CharStreams.fromReader(reader);

      var lexer = new CLexer(input);
      var tokens = new CommonTokenStream(lexer);
      var parser = new CParser(tokens);
      var result = new DefaultParseResult(this);
      parser.addErrorListener(new AntlrCErrorListener(result));
      parser.blockItemList();
      return result;
    } catch (IOException io) {
      Msg.error(getClass(), io);
    }
    return null;
  }
}
