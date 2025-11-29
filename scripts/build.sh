#!/bin/bash

# COD3X:RECON Build Script
# Compiles TypeScript and prepares distribution

set -e

echo "🔨 COD3X:RECON Build Script"
echo "=============================="
echo ""

# Clean previous build
echo "🧹 Cleaning previous build..."
rm -rf dist/
echo "✓ Clean complete"
echo ""

# Compile TypeScript
echo "📦 Compiling TypeScript..."
npx tsc
echo "✓ TypeScript compilation complete"
echo ""

# Compile external plugin
echo "📦 Compiling external plugin..."
if [ -d "plugins/example-external-plugin" ]; then
  npx tsc plugins/example-external-plugin/index.ts \
    --target ES2022 \
    --module ES2022 \
    --moduleResolution node \
    --outDir plugins/example-external-plugin
fi

# Make CLI executable
echo "🔧 Making CLI executable..."
chmod +x dist/cli/index.js
echo "✓ CLI is now executable"
echo ""

# Optional: Bundle with esbuild for smaller output
# Uncomment to enable bundling
# echo "📦 Bundling with esbuild..."
# npx esbuild dist/cli/index.js \
#   --bundle \
#   --platform=node \
#   --target=node18 \
#   --outfile=dist/bundle/cod3x.js \
#   --external:undici \
#   --external:chalk \
#   --external:commander \
#   --external:p-limit \
#   --external:lru-cache
# chmod +x dist/bundle/cod3x.js
# echo "✓ Bundling complete"
# echo ""

# Copy static files
echo "📋 Copying static files..."
cp -r templates dist/ 2>/dev/null || true
cp -r src/nuclei/templates dist/nuclei/ 2>/dev/null || true
echo "✓ Static files copied"
echo ""

# Generate package info
echo "📝 Generating build info..."
cat > dist/BUILD_INFO.txt << EOF
COD3X:RECON Build Information
============================

Build Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Node Version: $(node --version)
TypeScript Version: $(npx tsc --version)
Platform: $(uname -s)
Architecture: $(uname -m)

Build completed successfully!
EOF
echo "✓ Build info generated"
echo ""

# Show build size
echo "📊 Build Statistics:"
echo "-------------------"
du -sh dist/
echo ""

echo "✅ Build completed successfully!"
echo ""
echo "Run with: npm start -- scan -d example.com"
echo "Or install globally: npm link"
echo ""