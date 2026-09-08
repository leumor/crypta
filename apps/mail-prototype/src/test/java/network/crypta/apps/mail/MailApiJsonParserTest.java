package network.crypta.apps.mail;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MailApiJsonParserTest {
  @Test
  void nullArrayMembersRemainJsonNullInImmutableNestedArrays() {
    List<?> array =
        assertInstanceOf(List.class, MailApiJsonParser.parse("[null,[null],{\"a\":[null]}]"));

    assertNull(array.get(0));
    assertNull(assertInstanceOf(List.class, array.get(1)).getFirst());
    Map<?, ?> object = assertInstanceOf(Map.class, array.get(2));
    assertNull(assertInstanceOf(List.class, object.get("a")).getFirst());
    assertThrows(UnsupportedOperationException.class, array::clear);
  }

  @Test
  void malformedArraysRejectWithValidationException() {
    for (String json : List.of("[null,]", "[null", "[nul]", "[null] trailing")) {
      assertThrows(IllegalArgumentException.class, () -> MailApiJsonParser.parse(json));
    }
  }
}
