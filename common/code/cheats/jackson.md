# Read Object List From JSON Array String

List<Car> cars1 = objectMapper.readValue(jsonArray, new TypeReference<List<Car>>(){});

# Serialization features/options

http://www.baeldung.com/jackson-object-mapper-tutorial
https://github.com/FasterXML/jackson-databind/wiki/Serialization-Features
