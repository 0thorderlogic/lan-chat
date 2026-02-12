FROM denoland/deno:alpine-1.40.2

WORKDIR /app

# Prefer not to run as root.
USER deno

# Cache dependencies
COPY deno.json .
RUN deno cache --allow-import npm:esbuild

COPY . .

# Build the frontend
RUN deno task build:fe

# Expose the port
EXPOSE 8000

# Run the server
CMD ["deno", "task", "start"]
