const connectDB = async () => {
  console.log('✅ Conexión a PostgreSQL simulada');
};

const query = async (text, params) => {
  console.log('Query:', text);
  return { rows: [] };
};

module.exports = { connectDB, query };
