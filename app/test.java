import java.util.*;
import java.time.LocalDateTime;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ECommerceApp {
    public static void main(String[] args) {
        ECommerceSystem system = new ECommerceSystem();
        system.initialize();
    }
}

class ECommerceSystem {
    private UserManager userManager;
    private ProductCatalog productCatalog;
    private ShoppingCartManager cartManager;
    private OrderProcessor orderProcessor;
    private InventoryManager inventoryManager;
    private PaymentProcessor paymentProcessor;
    private Logger logger;
    private DatabaseConnection dbConnection;

    public void initialize() {
        logger = new Logger();
        dbConnection = new DatabaseConnection();
        userManager = new UserManager(dbConnection, logger);
        productCatalog = new ProductCatalog(dbConnection, logger);
        cartManager = new ShoppingCartManager(logger);
        inventoryManager = new InventoryManager(dbConnection, logger);
        paymentProcessor = new PaymentProcessor(logger);
        orderProcessor = new OrderProcessor(dbConnection, inventoryManager, paymentProcessor, logger);
    }
}

class User {
    private int id;
    private String username;
    private String passwordHash;
    private String email;
    private String firstName;
    private String lastName;
    private Address address;
    private List<Order> orderHistory;
    private UserRole role;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    public User(String username, String email, String firstName, String lastName) {
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.orderHistory = new ArrayList<>();
        this.createdAt = LocalDateTime.now();
        this.role = UserRole.CUSTOMER;
    }

    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public Address getAddress() { return address; }
    public void setAddress(Address address) { this.address = address; }
    public List<Order> getOrderHistory() { return orderHistory; }
    public UserRole getRole() { return role; }
    public void setRole(UserRole role) { this.role = role; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getLastLogin() { return lastLogin; }
    public void setLastLogin(LocalDateTime lastLogin) { this.lastLogin = lastLogin; }
}

enum UserRole {
    CUSTOMER,
    ADMIN,
    MANAGER
}

class Address {
    private String street;
    private String city;
    private String state;
    private String zipCode;
    private String country;

    public Address(String street, String city, String state, String zipCode, String country) {
        this.street = street;
        this.city = city;
        this.state = state;
        this.zipCode = zipCode;
        this.country = country;
    }

    // Getters and setters
    public String getStreet() { return street; }
    public String getCity() { return city; }
    public String getState() { return state; }
    public String getZipCode() { return zipCode; }
    public String getCountry() { return country; }
}

class Product {
    private int id;
    private String name;
    private String description;
    private BigDecimal price;
    private String category;
    private int stockQuantity;
    private List<ProductReview> reviews;
    private String imageUrl;
    private boolean active;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public Product(String name, String description, BigDecimal price, String category) {
        this.name = name;
        this.description = description;
        this.price = price;
        this.category = category;
        this.reviews = new ArrayList<>();
        this.active = true;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public BigDecimal getPrice() { return price; }
    public void setPrice(BigDecimal price) { 
        this.price = price;
        this.updatedAt = LocalDateTime.now();
    }
    public String getCategory() { return category; }
    public int getStockQuantity() { return stockQuantity; }
    public void setStockQuantity(int quantity) { 
        this.stockQuantity = quantity;
        this.updatedAt = LocalDateTime.now();
    }
    public List<ProductReview> getReviews() { return reviews; }
    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}

class ProductReview {
    private int id;
    private User user;
    private Product product;
    private int rating;
    private String comment;
    private LocalDateTime createdAt;

    public ProductReview(User user, Product product, int rating, String comment) {
        this.user = user;
        this.product = product;
        this.rating = rating;
        this.comment = comment;
        this.createdAt = LocalDateTime.now();
    }

    // Getters
    public int getId() { return id; }
    public User getUser() { return user; }
    public Product getProduct() { return product; }
    public int getRating() { return rating; }
    public String getComment() { return comment; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}

class ShoppingCart {
    private User user;
    private List<CartItem> items;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public ShoppingCart(User user) {
        this.user = user;
        this.items = new ArrayList<>();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public void addItem(Product product, int quantity) {
        CartItem existingItem = findItem(product);
        if (existingItem != null) {
            existingItem.setQuantity(existingItem.getQuantity() + quantity);
        } else {
            items.add(new CartItem(product, quantity));
        }
        this.updatedAt = LocalDateTime.now();
    }

    public void removeItem(Product product) {
        items.removeIf(item -> item.getProduct().getId() == product.getId());
        this.updatedAt = LocalDateTime.now();
    }

    public void updateItemQuantity(Product product, int quantity) {
        CartItem item = findItem(product);
        if (item != null) {
            item.setQuantity(quantity);
            this.updatedAt = LocalDateTime.now();
        }
    }

    private CartItem findItem(Product product) {
        return items.stream()
                   .filter(item -> item.getProduct().getId() == product.getId())
                   .findFirst()
                   .orElse(null);
    }

    public BigDecimal getTotal() {
        return items.stream()
                   .map(item -> item.getProduct().getPrice()
                                  .multiply(BigDecimal.valueOf(item.getQuantity())))
                   .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    // Getters
    public User getUser() { return user; }
    public List<CartItem> getItems() { return items; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}

class CartItem {
    private Product product;
    private int quantity;

    public CartItem(Product product, int quantity) {
        this.product = product;
        this.quantity = quantity;
    }

    // Getters and setters
    public Product getProduct() { return product; }
    public int getQuantity() { return quantity; }
    public void setQuantity(int quantity) { this.quantity = quantity; }
}

class Order {
    private int id;
    private User user;
    private List<OrderItem> items;
    private BigDecimal total;
    private OrderStatus status;
    private PaymentInfo paymentInfo;
    private Address shippingAddress;
    private String trackingNumber;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public Order(User user, List<CartItem> cartItems, Address shippingAddress) {
        this.user = user;
        this.items = cartItems.stream()
                             .map(item -> new OrderItem(item.getProduct(), item.getQuantity()))
                             .toList();
        this.shippingAddress = shippingAddress;
        this.status = OrderStatus.PENDING;
        this.total = calculateTotal();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    private BigDecimal calculateTotal() {
        return items.stream()
                   .map(item -> item.getProduct().getPrice()
                                  .multiply(BigDecimal.valueOf(item.getQuantity())))
                   .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public User getUser() { return user; }
    public List<OrderItem> getItems() { return items; }
    public BigDecimal getTotal() { return total; }
    public OrderStatus getStatus() { return status; }
    public void setStatus(OrderStatus status) { 
        this.status = status;
        this.updatedAt = LocalDateTime.now();
    }
    public PaymentInfo getPaymentInfo() { return paymentInfo; }
    public void setPaymentInfo(PaymentInfo paymentInfo) { this.paymentInfo = paymentInfo; }
    public Address getShippingAddress() { return shippingAddress; }
    public String getTrackingNumber() { return trackingNumber; }
    public void setTrackingNumber(String trackingNumber) { this.trackingNumber = trackingNumber; }
}

enum OrderStatus {
    PENDING,
    PAID,
    PROCESSING,
    SHIPPED,
    DELIVERED,
    CANCELLED,
    REFUNDED
}

class OrderItem {
    private Product product;
    private int quantity;
    private BigDecimal priceAtTime;

    public OrderItem(Product product, int quantity) {
        this.product = product;
        this.quantity = quantity;
        this.priceAtTime = product.getPrice();
    }

    // Getters
    public Product getProduct() { return product; }
    public int getQuantity() { return quantity; }
    public BigDecimal getPriceAtTime() { return priceAtTime; }
}

class PaymentInfo {
    private String transactionId;
    private PaymentMethod method;
    private BigDecimal amount;
    private String currency;
    private PaymentStatus status;
    private LocalDateTime processedAt;

    public PaymentInfo(PaymentMethod method, BigDecimal amount, String currency) {
        this.method = method;
        this.amount = amount;
        this.currency = currency;
        this.status = PaymentStatus.PENDING;
    }

    // Getters and setters
    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
    public PaymentMethod getMethod() { return method; }
    public BigDecimal getAmount() { return amount; }
    public String getCurrency() { return currency; }
    public PaymentStatus getStatus() { return status; }
    public void setStatus(PaymentStatus status) { this.status = status; }
    public LocalDateTime getProcessedAt() { return processedAt; }
    public void setProcessedAt(LocalDateTime processedAt) { this.processedAt = processedAt; }
}

enum PaymentMethod {
    CREDIT_CARD,
    DEBIT_CARD,
    PAYPAL,
    BANK_TRANSFER
}

enum PaymentStatus {
    PENDING,
    COMPLETED,
    FAILED,
    REFUNDED
}

class UserManager {
    private DatabaseConnection dbConnection;
    private Logger logger;

    public UserManager(DatabaseConnection dbConnection, Logger logger) {
        this.dbConnection = dbConnection;
        this.logger = logger;
    }

    public User createUser(String username, String password, String email, 
                          String firstName, String lastName) throws Exception {
        if (!isValidEmail(email)) {
            throw new IllegalArgumentException("Invalid email format");
        }

        if (!isValidPassword(password)) {
            throw new IllegalArgumentException("Password does not meet requirements");
        }

        if (userExists(username, email)) {
            throw new IllegalArgumentException("Username or email already exists");
        }

        User user = new User(username, email, firstName, lastName);
        user.setPasswordHash(hashPassword(password));

        saveUser(user);
        logger.log("User created: " + username);
        return user;
    }

    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
    }

    private boolean isValidPassword(String password) {
        return password != null && password.length() >= 8 &&
               password.matches(".*[A-Z].*") && 
               password.matches(".*[a-z].*") &&
               password.matches(".*[0-9].*");
    }

    private boolean userExists(String username, String email) {
        try {
            String sql = "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, email);
            ResultSet rs = stmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } catch (SQLException e) {
            logger.error("Error checking user existence: " + e.getMessage());
            return false;
        }
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error hashing password: " + e.getMessage());
            throw new RuntimeException("Error hashing password", e);
        }
    }

    private void saveUser(User user) {
        try {
            String sql = "INSERT INTO users (username, password_hash, email, first_name, " +
                        "last_name, created_at) VALUES (?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getPasswordHash());
            stmt.setString(3, user.getEmail());
            stmt.setString(4, user.getFirstName());
            stmt.setString(5, user.getLastName());
            stmt.setObject(6, user.getCreatedAt());
            stmt.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error saving user: " + e.getMessage());
            throw new RuntimeException("Error saving user", e);
        }
    }
}

class ProductCatalog {
    private DatabaseConnection dbConnection;
    private Logger logger;

    public ProductCatalog(DatabaseConnection dbConnection, Logger logger) {
        this.dbConnection = dbConnection;
        this.logger = logger;
    }

    public void addProduct(Product product) {
        try {
            String sql = "INSERT INTO products (name, description, price, category, " +
                        "stock_quantity, image_url, active, created_at, updated_at) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setString(1, product.getName());
            stmt.setString(2, product.getDescription());
            stmt.setBigDecimal(3, product.getPrice());
            stmt.setString(4, product.getCategory());
            stmt.setInt(5, product.getStockQuantity());
            stmt.setString(6, product.getImageUrl());
            stmt.setBoolean(7, product.isActive());
            stmt.setObject(8, product.getCreatedAt());
            stmt.setObject(9, product.getUpdatedAt());
            stmt.executeUpdate();
            logger.log("Product added: " + product.getName());
        } catch (SQLException e) {
            logger.error("Error adding product: " + e.getMessage());
            throw new RuntimeException("Error adding product", e);
        }
    }

    public List<Product> searchProducts(String query, String category, 
                                      BigDecimal minPrice, BigDecimal maxPrice) {
        List<Product> results = new ArrayList<>();
        try {
            StringBuilder sql = new StringBuilder(
                "SELECT * FROM products WHERE active = true"
            );
            List<Object> params = new ArrayList<>();

            if (query != null && !query.isEmpty()) {
                sql.append(" AND (LOWER(name) LIKE ? OR LOWER(description) LIKE ?)");
                String searchPattern = "%" + query.toLowerCase() + "%";
                params.add(searchPattern);
                params.add(searchPattern);
            }

            if (category != null && !category.isEmpty()) {
                sql.append(" AND category = ?");
                params.add(category);
            }

            if (minPrice != null) {
                sql.append(" AND price >= ?");
                params.add(minPrice);
            }

            if (maxPrice != null) {
                sql.append(" AND price <= ?");
                params.add(maxPrice);
            }

            PreparedStatement stmt = dbConnection.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                results.add(mapResultSetToProduct(rs));
            }
        } catch (SQLException e) {
            logger.error("Error searching products: " + e.getMessage());
            throw new RuntimeException("Error searching products", e);
        }
        return results;
    }

    private Product mapResultSetToProduct(ResultSet rs) throws SQLException {
        Product product = new Product(
            rs.getString("name"),
            rs.getString("description"),
            rs.getBigDecimal("price"),
            rs.getString("category")
        );
        product.setId(rs.getInt("id"));
        product.setStockQuantity(rs.getInt("stock_quantity"));
        product.setImageUrl(rs.getString("image_url"));
        product.setActive(rs.getBoolean("active"));
        return product;
    }
}

class DatabaseConnection {
    private Connection connection;
    private static final String DB_URL = "jdbc:postgresql://localhost:5432/ecommerce";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "secret";

    public DatabaseConnection() {
        try {
            connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        } catch (SQLException e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    public PreparedStatement prepareStatement(String sql) throws SQLException {
        return connection.prepareStatement(sql);
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Error closing database connection", e);
        }
    }
}

class Logger {
    public void log(String message) {
        System.out.println("[INFO] " + LocalDateTime.now() + " - " + message);
    }

    public void error(String message) {
        System.err.println("[ERROR] " + LocalDateTime.now() + " - " + message);
    }
}

class ShoppingCartManager {
    private Map<Integer, ShoppingCart> carts;
    private Logger logger;

    public ShoppingCartManager(Logger logger) {
        this.carts = new HashMap<>();
        this.logger = logger;
    }

    public ShoppingCart getCart(User user) {
        return carts.computeIfAbsent(user.getId(), k -> new ShoppingCart(user));
    }

    public void addToCart(User user, Product product, int quantity) {
        if (quantity <= 0) {
            throw new IllegalArgumentException("Quantity must be positive");
        }

        ShoppingCart cart = getCart(user);
        cart.addItem(product, quantity);
        logger.log("Added " + quantity + " x " + product.getName() + " to cart for user: " + user.getUsername());
    }

    public void removeFromCart(User user, Product product) {
        ShoppingCart cart = getCart(user);
        cart.removeItem(product);
        logger.log("Removed " + product.getName() + " from cart for user: " + user.getUsername());
    }

    public void updateQuantity(User user, Product product, int quantity) {
        if (quantity <= 0) {
            throw new IllegalArgumentException("Quantity must be positive");
        }

        ShoppingCart cart = getCart(user);
        cart.updateItemQuantity(product, quantity);
        logger.log("Updated quantity for " + product.getName() + " to " + quantity + 
                  " in cart for user: " + user.getUsername());
    }

    public void clearCart(User user) {
        carts.remove(user.getId());
        logger.log("Cleared cart for user: " + user.getUsername());
    }
}

class OrderProcessor {
    private DatabaseConnection dbConnection;
    private InventoryManager inventoryManager;
    private PaymentProcessor paymentProcessor;
    private Logger logger;

    public OrderProcessor(DatabaseConnection dbConnection, 
                         InventoryManager inventoryManager,
                         PaymentProcessor paymentProcessor,
                         Logger logger) {
        this.dbConnection = dbConnection;
        this.inventoryManager = inventoryManager;
        this.paymentProcessor = paymentProcessor;
        this.logger = logger;
    }

    public Order createOrder(User user, ShoppingCart cart, PaymentMethod paymentMethod) {
        // Validate inventory
        for (CartItem item : cart.getItems()) {
            if (!inventoryManager.checkAvailability(item.getProduct(), item.getQuantity())) {
                throw new IllegalStateException("Insufficient inventory for " + 
                                              item.getProduct().getName());
            }
        }

        // Create order
        Order order = new Order(user, cart.getItems(), user.getAddress());
        saveOrder(order);

        // Process payment
        PaymentInfo paymentInfo = new PaymentInfo(paymentMethod, order.getTotal(), "USD");
        try {
            paymentProcessor.processPayment(paymentInfo);
            order.setPaymentInfo(paymentInfo);
            order.setStatus(OrderStatus.PAID);

            // Update inventory
            for (OrderItem item : order.getItems()) {
                inventoryManager.reduceStock(item.getProduct(), item.getQuantity());
            }

            updateOrder(order);
            logger.log("Order created successfully: " + order.getId());
            return order;
        } catch (Exception e) {
            order.setStatus(OrderStatus.CANCELLED);
            updateOrder(order);
            logger.error("Order creation failed: " + e.getMessage());
            throw new RuntimeException("Failed to process order", e);
        }
    }

    private void saveOrder(Order order) {
        try {
            String sql = "INSERT INTO orders (user_id, total, status, created_at, updated_at) " +
                        "VALUES (?, ?, ?, ?, ?) RETURNING id";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setInt(1, order.getUser().getId());
            stmt.setBigDecimal(2, order.getTotal());
            stmt.setString(3, order.getStatus().name());
            stmt.setObject(4, order.getCreatedAt());
            stmt.setObject(5, order.getUpdatedAt());
            
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                order.setId(rs.getInt(1));
            }

            // Save order items
            for (OrderItem item : order.getItems()) {
                saveOrderItem(order.getId(), item);
            }
        } catch (SQLException e) {
            logger.error("Error saving order: " + e.getMessage());
            throw new RuntimeException("Error saving order", e);
        }
    }

    private void saveOrderItem(int orderId, OrderItem item) throws SQLException {
        String sql = "INSERT INTO order_items (order_id, product_id, quantity, price_at_time) " +
                    "VALUES (?, ?, ?, ?)";
        PreparedStatement stmt = dbConnection.prepareStatement(sql);
        stmt.setInt(1, orderId);
        stmt.setInt(2, item.getProduct().getId());
        stmt.setInt(3, item.getQuantity());
        stmt.setBigDecimal(4, item.getPriceAtTime());
        stmt.executeUpdate();
    }

    private void updateOrder(Order order) {
        try {
            String sql = "UPDATE orders SET status = ?, updated_at = ? WHERE id = ?";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setString(1, order.getStatus().name());
            stmt.setObject(2, LocalDateTime.now());
            stmt.setInt(3, order.getId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error updating order: " + e.getMessage());
            throw new RuntimeException("Error updating order", e);
        }
    }
}

class InventoryManager {
    private DatabaseConnection dbConnection;
    private Logger logger;

    public InventoryManager(DatabaseConnection dbConnection, Logger logger) {
        this.dbConnection = dbConnection;
        this.logger = logger;
    }

    public boolean checkAvailability(Product product, int quantity) {
        try {
            String sql = "SELECT stock_quantity FROM products WHERE id = ?";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setInt(1, product.getId());
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                int available = rs.getInt("stock_quantity");
                return available >= quantity;
            }
            return false;
        } catch (SQLException e) {
            logger.error("Error checking inventory: " + e.getMessage());
            throw new RuntimeException("Error checking inventory", e);
        }
    }

    public void reduceStock(Product product, int quantity) {
        try {
            String sql = "UPDATE products SET stock_quantity = stock_quantity - ? " +
                        "WHERE id = ? AND stock_quantity >= ?";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setInt(1, quantity);
            stmt.setInt(2, product.getId());
            stmt.setInt(3, quantity);
            
            int updated = stmt.executeUpdate();
            if (updated == 0) {
                throw new IllegalStateException("Failed to update inventory for product: " + 
                                              product.getId());
            }
            
            logger.log("Reduced stock for product " + product.getName() + " by " + quantity);
        } catch (SQLException e) {
            logger.error("Error reducing stock: " + e.getMessage());
            throw new RuntimeException("Error reducing stock", e);
        }
    }

    public void restockProduct(Product product, int quantity) {
        try {
            String sql = "UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setInt(1, quantity);
            stmt.setInt(2, product.getId());
            
            stmt.executeUpdate();
            logger.log("Restocked product " + product.getName() + " with " + quantity + " units");
        } catch (SQLException e) {
            logger.error("Error restocking product: " + e.getMessage());
            throw new RuntimeException("Error restocking product", e);
        }
    }
}

class PaymentProcessor {
    private Logger logger;

    public PaymentProcessor(Logger logger) {
        this.logger = logger;
    }

    public void processPayment(PaymentInfo paymentInfo) {
        // Simulate payment processing
        try {
            Thread.sleep(1000); // Simulate API call
            
            // Generate transaction ID
            String transactionId = generateTransactionId();
            paymentInfo.setTransactionId(transactionId);
            paymentInfo.setStatus(PaymentStatus.COMPLETED);
            paymentInfo.setProcessedAt(LocalDateTime.now());
            
            logger.log("Payment processed successfully: " + transactionId);
        } catch (InterruptedException e) {
            logger.error("Payment processing interrupted: " + e.getMessage());
            paymentInfo.setStatus(PaymentStatus.FAILED);
            throw new RuntimeException("Payment processing failed", e);
        }
    }

    private String generateTransactionId() {
        return "TXN" + System.currentTimeMillis() + 
               String.format("%04d", new Random().nextInt(10000));
    }
}
