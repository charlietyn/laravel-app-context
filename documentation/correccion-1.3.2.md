# 1.3.2 — clientes con borrado lógico opcional

El repositorio Eloquent consultaba siempre `deleted_at`. Los proyectos que deciden no usar
borrado lógico fallaban al recuperar un cliente, listar clientes o repetir el setup de pagos.

Ahora comprueba la existencia de esa columna en la conexión y tabla resueltas por configuración
o modelos. Si existe, mantiene la exclusión de clientes borrados, incluso al incluir inactivos.
Si no existe, la consulta no referencia una columna inexistente. No añade ni modifica tablas.
La detección se conserva por instancia del repositorio para evitar consultas de esquema repetidas.

Las pruebas utilizan SQLite en memoria y cubren tablas directas/modelos, conexiones distintas de
la predeterminada y tablas con/sin borrado lógico; verifican consulta, clave, listado, uso y revocación.
Publicación pendiente de autorización; no se modifica ningún tag ni paquete anterior.
