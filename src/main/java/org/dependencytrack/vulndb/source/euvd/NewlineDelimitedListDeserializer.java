package org.dependencytrack.vulndb.source.euvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.List;

public final class NewlineDelimitedListDeserializer extends JsonDeserializer<List<String>> {

    @Override
    public List<String> deserialize(
            final JsonParser jsonParser,
            final DeserializationContext deserializationContext) throws IOException {
        return jsonParser.readValueAs(String.class).lines().toList();
    }

}
