import static org.junit.jupiter.api.Assertions.*;

import org.example.LoginApp;
import org.junit.jupiter.api.Test;
import java.sql.*;

public class TestLoginApp {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/softwaretesting";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "12345678";

    @Test
    public void testValidLogin() {
        LoginApp loginApp = new LoginApp();

        // Simulating valid login credentials
        String validEmail = "johndoe@example.com";
        String validPassword = "password123";

        boolean isAuthenticated = loginApp.authenticateUser(validEmail, validPassword);

        // Asserts: Ensure the user is authenticated with valid credentials
        assertTrue(isAuthenticated, "User should be authenticated with valid credentials");

        // Check if user exists in database
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM User WHERE Email = ? AND Password = ?";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, validEmail);
            stmt.setString(2, validPassword);
            ResultSet rs = stmt.executeQuery();

            // Asserts: Ensure user exists in the database with matching credentials
            assertTrue(rs.next(), "User should exist in the database with matching credentials");
            assertEquals(validEmail, rs.getString("Email"), "Emails should match");
            assertEquals(validPassword, rs.getString("Password"), "Passwords should match");
        } catch (SQLException e) {
            e.printStackTrace();
            fail("Database query failed");
        }
    }

    @Test
    public void testInvalidLogin() {
        LoginApp loginApp = new LoginApp();

        // Simulating invalid login credentials
        String invalidEmail = "invalid@example.com";
        String invalidPassword = "wrongpassword";

        boolean isAuthenticated = loginApp.authenticateUser(invalidEmail, invalidPassword);

        // Asserts: Ensure the user is NOT authenticated with invalid credentials
        assertFalse(isAuthenticated, "User should not be authenticated with invalid credentials");

        // Test that the error message is shown (if applicable)
        // In a real test, you might need to mock JOptionPane or use a different strategy
        // assertEquals("Invalid email or password.", getDisplayedMessage());

        // Check that the user does not exist in the database
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM User WHERE Email = ? AND Password = ?";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, invalidEmail);
            stmt.setString(2, invalidPassword);
            ResultSet rs = stmt.executeQuery();

            // Asserts: Ensure no user is found with invalid credentials
            assertFalse(rs.next(), "User should not be found with invalid credentials");
        } catch (SQLException e) {
            e.printStackTrace();
            fail("Database query failed");
        }
    }

    @Test
    public void testValidLoginFailsForIncorrectImplementation() {
        LoginApp loginApp = new LoginApp();

        // Simulating valid login credentials
        String validEmail = "johndoe@example.com";
        String validPassword = "password123";

        // Add a test case where the password is incorrect but the email exists
        String incorrectPassword = "wrongPassword123";

        // Attempt to authenticate with correct email and incorrect password
        boolean isAuthenticated = loginApp.authenticateUser(validEmail, incorrectPassword);

        // The test will fail because the current implementation only checks email
        assertFalse(isAuthenticated, "User should not be authenticated with incorrect password");
    }

    @Test
    public void testDatabaseConnection() {
        // Asserts: Ensure that the database connection is valid
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            assertNotNull(conn, "Database connection should not be null");
            assertTrue(conn.isValid(2), "Database connection should be valid");
        } catch (SQLException e) {
            e.printStackTrace();
            fail("Database connection failed");
        }
    }

    @Test
    public void testSQLInjectionProtection() {
        LoginApp loginApp = new LoginApp();

        // Simulating a potential SQL injection attempt
        String sqlInjectionEmail = "admin' --";
        String sqlInjectionPassword = "password123";

        boolean isAuthenticated = loginApp.authenticateUser(sqlInjectionEmail, sqlInjectionPassword);

        // Asserts: Ensure the application is protected against SQL injection
        assertFalse(isAuthenticated, "SQL injection attempt should not authenticate the user");

        // Check if the SQL injection is handled correctly by ensuring no user is returned
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM User WHERE Email = ? AND Password = ?";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, sqlInjectionEmail);
            stmt.setString(2, sqlInjectionPassword);
            ResultSet rs = stmt.executeQuery();

            // Asserts: Ensure no user is found for the SQL injection attempt
            assertFalse(rs.next(), "User should not be found with SQL injection email");
        } catch (SQLException e) {
            e.printStackTrace();
            fail("Database query failed");
        }
    }
}
