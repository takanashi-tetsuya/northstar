export const MAX_AVATAR_INPUT_BYTES = 50 * 1024 * 1024;
export const MAX_AVATAR_OUTPUT_BYTES = (256 * 1024) - 1;
export const AVATAR_EDITOR_SIZE = 360;

function canvasToBlob(canvas, type, quality) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) resolve(blob);
      else reject(new Error('浏览器无法生成处理后的头像'));
    }, type, quality);
  });
}

async function decodeWithImageBitmap(file) {
  if (!globalThis.createImageBitmap) return null;
  try {
    const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
    return {
      drawable: bitmap,
      width: bitmap.width,
      height: bitmap.height,
      cleanup: () => bitmap.close(),
    };
  } catch {
    try {
      const bitmap = await createImageBitmap(file);
      return {
        drawable: bitmap,
        width: bitmap.width,
        height: bitmap.height,
        cleanup: () => bitmap.close(),
      };
    } catch {
      return null;
    }
  }
}

async function decodeWithWebCodecs(file) {
  if (!globalThis.ImageDecoder || !file.type) return null;
  try {
    if (!(await ImageDecoder.isTypeSupported(file.type))) return null;
    const decoder = new ImageDecoder({ data: await file.arrayBuffer(), type: file.type });
    const { image } = await decoder.decode({ frameIndex: 0 });
    return {
      drawable: image,
      width: image.displayWidth,
      height: image.displayHeight,
      cleanup: () => {
        image.close();
        decoder.close();
      },
    };
  } catch {
    return null;
  }
}

async function decodeWithImageElement(file) {
  const url = URL.createObjectURL(file);
  const image = new Image();
  image.decoding = 'async';
  image.src = url;
  try {
    await image.decode();
    return {
      drawable: image,
      width: image.naturalWidth,
      height: image.naturalHeight,
      cleanup: () => URL.revokeObjectURL(url),
    };
  } catch {
    URL.revokeObjectURL(url);
    return null;
  }
}

async function decodeAvatar(file) {
  const decoded = await decodeWithImageBitmap(file)
    || await decodeWithWebCodecs(file)
    || await decodeWithImageElement(file);
  if (!decoded?.width || !decoded?.height) throw new Error('当前浏览器无法读取这种图片格式');
  if (decoded.width > 32768 || decoded.height > 32768 || decoded.width * decoded.height > 120_000_000) {
    decoded.cleanup();
    throw new Error('图片像素尺寸过大，无法安全处理');
  }
  return decoded;
}

export function formatAvatarBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export class AvatarCropper {
  constructor(canvas) {
    this.canvas = canvas;
    this.context = canvas.getContext('2d', { alpha: false });
    this.source = null;
    this.rotation = 0;
    this.zoom = 1;
    this.offsetX = 0;
    this.offsetY = 0;
    const pixelRatio = Math.min(globalThis.devicePixelRatio || 1, 2);
    canvas.width = AVATAR_EDITOR_SIZE * pixelRatio;
    canvas.height = AVATAR_EDITOR_SIZE * pixelRatio;
    this.pixelRatio = pixelRatio;
    this.render();
  }

  async load(file) {
    this.clear();
    this.source = await decodeAvatar(file);
    this.reset();
    return { width: this.source.width, height: this.source.height };
  }

  clear() {
    this.source?.cleanup?.();
    this.source = null;
    this.rotation = 0;
    this.zoom = 1;
    this.offsetX = 0;
    this.offsetY = 0;
    this.render();
  }

  reset() {
    this.rotation = 0;
    this.zoom = 1;
    this.offsetX = 0;
    this.offsetY = 0;
    this.render();
  }

  setZoom(value) {
    this.zoom = Math.min(4, Math.max(1, Number(value) || 1));
    this.constrainOffsets();
    this.render();
  }

  rotate(delta) {
    this.rotation = (this.rotation + delta + 360) % 360;
    this.offsetX = 0;
    this.offsetY = 0;
    this.constrainOffsets();
    this.render();
  }

  moveBy(deltaX, deltaY) {
    this.offsetX += deltaX;
    this.offsetY += deltaY;
    this.constrainOffsets();
    this.render();
  }

  rotatedDimensions() {
    if (!this.source) return { width: 0, height: 0 };
    const quarterTurn = Math.abs(this.rotation % 180) === 90;
    return quarterTurn
      ? { width: this.source.height, height: this.source.width }
      : { width: this.source.width, height: this.source.height };
  }

  scale() {
    const dimensions = this.rotatedDimensions();
    if (!dimensions.width || !dimensions.height) return 1;
    return Math.max(AVATAR_EDITOR_SIZE / dimensions.width, AVATAR_EDITOR_SIZE / dimensions.height) * this.zoom;
  }

  constrainOffsets() {
    const dimensions = this.rotatedDimensions();
    const scale = this.scale();
    const maxX = Math.max(0, ((dimensions.width * scale) - AVATAR_EDITOR_SIZE) / 2);
    const maxY = Math.max(0, ((dimensions.height * scale) - AVATAR_EDITOR_SIZE) / 2);
    this.offsetX = Math.min(maxX, Math.max(-maxX, this.offsetX));
    this.offsetY = Math.min(maxY, Math.max(-maxY, this.offsetY));
  }

  draw(context, size) {
    context.save();
    context.fillStyle = '#f4f5ef';
    context.fillRect(0, 0, size, size);
    if (this.source) {
      const ratio = size / AVATAR_EDITOR_SIZE;
      context.translate((size / 2) + (this.offsetX * ratio), (size / 2) + (this.offsetY * ratio));
      context.rotate((this.rotation * Math.PI) / 180);
      const scale = this.scale() * ratio;
      context.scale(scale, scale);
      context.drawImage(this.source.drawable, -this.source.width / 2, -this.source.height / 2);
    }
    context.restore();
  }

  render() {
    const context = this.context;
    context.setTransform(this.pixelRatio, 0, 0, this.pixelRatio, 0, 0);
    context.clearRect(0, 0, AVATAR_EDITOR_SIZE, AVATAR_EDITOR_SIZE);
    this.draw(context, AVATAR_EDITOR_SIZE);
  }

  async exportAvatar() {
    if (!this.source) throw new Error('请先选择头像图片');
    const dimensions = [512, 448, 384, 320, 256, 224, 192];
    const qualities = [.92, .86, .8, .74, .68, .6, .52, .44, .36];
    for (const dimension of dimensions) {
      const output = document.createElement('canvas');
      output.width = dimension;
      output.height = dimension;
      this.draw(output.getContext('2d', { alpha: false }), dimension);
      for (const quality of qualities) {
        const blob = await canvasToBlob(output, 'image/jpeg', quality);
        if (blob.size <= MAX_AVATAR_OUTPUT_BYTES) return { blob, dimension, quality };
      }
    }
    throw new Error('无法将头像压缩到 256 KiB 以下');
  }
}
