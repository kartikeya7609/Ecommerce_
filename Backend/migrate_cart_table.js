const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'users.db');
console.log('Database path:', DB_PATH);

// Create database connection
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database at:', DB_PATH);
});

// Enable foreign keys
db.run('PRAGMA foreign_keys = OFF');

console.log('Starting cart table migration...');

// Migration steps using a transaction
db.serialize(() => {
  // Start transaction
  db.run('BEGIN TRANSACTION');
  
  try {
    // Step 1: Rename the existing cart table
    db.run('ALTER TABLE cart RENAME TO cart_old', function(err) {
      if (err) {
        console.error('Error renaming cart table:', err);
        throw err;
      }
      console.log('Renamed cart table to cart_old');
      
      // Step 2: Create a new cart table with the UNIQUE constraint
      db.run(`CREATE TABLE cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        title TEXT NOT NULL,
        price REAL NOT NULL,
        image TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, product_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`, function(err) {
        if (err) {
          console.error('Error creating new cart table:', err);
          throw err;
        }
        console.log('Created new cart table with UNIQUE constraint');
        
        // Step 3: Copy data from old table to new table
        db.run(`INSERT OR REPLACE INTO cart 
          (id, user_id, product_id, email, quantity, title, price, image, created_at)
          SELECT id, user_id, product_id, email, quantity, title, price, image, created_at 
          FROM cart_old`, function(err) {
          if (err) {
            console.error('Error copying data to new cart table:', err);
            throw err;
          }
          console.log('Copied data from old cart table to new cart table');
          
          // Step 4: Drop the old table
          db.run('DROP TABLE cart_old', function(err) {
            if (err) {
              console.error('Error dropping old cart table:', err);
              throw err;
            }
            console.log('Dropped old cart table');
            
            // Step 5: Recreate indexes
            db.run('CREATE INDEX IF NOT EXISTS idx_carts_user_id ON cart(user_id)', function(err) {
              if (err) {
                console.error('Error creating user_id index:', err);
                throw err;
              }
              
              db.run('CREATE INDEX IF NOT EXISTS idx_carts_product_id ON cart(product_id)', function(err) {
                if (err) {
                  console.error('Error creating product_id index:', err);
                  throw err;
                }
                
                // Commit transaction
                db.run('COMMIT', function(err) {
                  if (err) {
                    console.error('Error committing transaction:', err);
                    throw err;
                  }
                  console.log('Migration completed successfully!');
                  
                  // Close database connection
                  db.close((err) => {
                    if (err) {
                      console.error('Error closing database:', err);
                    }
                    console.log('Database connection closed');
                  });
                });
              });
            });
          });
        });
      });
    });
  } catch (error) {
    // Rollback transaction on error
    console.error('Migration failed, rolling back changes:', error);
    db.run('ROLLBACK');
    db.close();
  }
});