export async function handler(event) {
  const params = event.queryStringParameters || {};
  const mode = params.mode || "classes";

  if (mode === "classes") {
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ok: true,
        classes: ["TEST_KLASSE_1", "TEST_KLASSE_2"]
      })
    };
  }

  if (mode === "sessions") {
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ok: true,
        rows: []
      })
    };
  }

  return {
    statusCode: 400,
    body: JSON.stringify({ ok: false, error: "Unknown mode" })
  };
}
