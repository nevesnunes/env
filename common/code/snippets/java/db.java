import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import org.apache.commons.dbutils.DbUtils;

// ...

Connection connection = null;
Statement statement = null;
ResultSet resultSet = null;
PreparedStatement statement = null;
try {
    connection = DriverManager.getConnection(url);
    connection.setAutoCommit(false);

    statement = connection.prepareStatement(QUERY_1);
    statement.setString(1, id);
    int result = statement.executeUpdate();

    // ...

    statement = connection.createStatement();
    resultSet = statement.executeQuery(QUERY_2);

    // ...

    connection.commit();
} catch (Exception e) {
    log.error(e);
    DbUtils.rollbackAndCloseQuietly(connection);
} finally {
    DbUtils.closeQuietly(statement);
    DbUtils.closeQuietly(resultSet);
    DbUtils.closeQuietly(statement);
    DbUtils.closeQuietly(connection);
}
