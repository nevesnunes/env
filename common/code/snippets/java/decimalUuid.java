UUID uuid = UUID.randomUUID();
String randomUUIDString = uuid.toString().replaceAll('-', '');
String decimalUUID = "";
for (int i = 0; i < randomUUIDString.length(); i++) {
    decimalUUID += String.format("%03d", (int) randomUUIDString.charAt(i));
}
