# Documentación del Sistema de Gestión de Call Center (DOV Agent Backend)

## 1. Descripción General
Esta aplicación es una solución integral para la gestión de operaciones de Call Center, diseñada para facilitar la interacción entre Administradores y Agentes. Permite la distribución eficiente de leads (clientes potenciales), el seguimiento de llamadas y el análisis de rendimiento en tiempo real, integrándose con la telefonía de RingCentral.

## 2. Arquitectura y Funcionamiento

### Backend (El Motor)
- **Tecnología**: Node.js con Express.js.
- **Base de Datos**: MongoDB (NoSQL) para un almacenamiento flexible y escalable de usuarios y leads.
- **Autenticación**: Sistema seguro basado en JWT (JSON Web Tokens) para proteger las rutas y diferenciar roles (Admin vs Agente).
- **Comunicación en Tiempo Real**: Implementación de **Socket.io** para que los cambios (como una nueva disposición de llamada) se reflejen instantáneamente en el panel del administrador sin necesidad de recargar la página.

### Frontend (La Interfaz)
- **Tecnología**: Vanilla JavaScript, HTML5 y CSS3.
- **Diseño**: Interfaz limpia y moderna con soporte para **Modo Oscuro**, optimizada para la productividad.
- **Experiencia de Usuario**: Uso de notificaciones tipo "Toast" para feedback inmediato y modales para interacciones fluidas.

### Integraciones
- **RingCentral API**: Conexión directa con la plataforma de telefonía para extraer estadísticas de llamadas (duración, cantidad) y compararlas con la productividad registrada en la app.

## 3. Cualidades y Funcionalidades Clave

### Para el Administrador
- **Gestión de Usuarios**: Crear, editar y eliminar cuentas de agentes.
- **Gestión de Leads**:
    - Carga masiva de leads mediante archivos CSV.
    - Asignación y reasignación inteligente de leads a agentes específicos.
    - Filtrado avanzado por fecha, disposición, producto o lista.
- **Dashboard de Analítica**:
    - Vista global del rendimiento del Call Center.
    - Estadísticas detalladas por agente (Tasa de Contacto, Tasa de Conversión).
    - Integración de métricas de telefonía (RingCentral).

### Para el Agente
- **Flujo de Trabajo Optimizado**: Interfaz enfocada en "un lead a la vez" para minimizar distracciones.
- **Historial y Seguimiento**: Registro automático de todas las interacciones con un cliente.
- **Gestión de Callbacks**: Sistema para agendar y recordar llamadas de seguimiento.
- **Métricas Personales**: Visualización de su propio progreso y estadísticas diarias.

## 4. Fortalezas del Sistema

1.  **Reactividad (Real-Time)**: La capacidad de ver la actividad de los agentes en vivo permite a los supervisores tomar decisiones inmediatas.
2.  **Escalabilidad**: Al usar MongoDB, el sistema puede manejar grandes volúmenes de datos (miles de leads) sin perder rendimiento.
3.  **Seguridad**: Protección robusta con encriptación de contraseñas (bcryptjs), headers de seguridad (Helmet) y limitación de tasa de peticiones (Rate Limiting) para evitar ataques de fuerza bruta.
4.  **Flexibilidad**: El sistema de filtrado y la capacidad de manejar múltiples listas de leads permiten adaptar la herramienta a diferentes campañas o productos.
5.  **Integración Unificada**: Combina la gestión de datos (CRM) con las métricas de telefonía en un solo lugar, eliminando la necesidad de consultar múltiples plataformas.
6.  **Resiliencia**: Manejo de errores robusto, incluyendo correcciones automáticas para desincronización de relojes (Clock Skew) con APIs externas.
