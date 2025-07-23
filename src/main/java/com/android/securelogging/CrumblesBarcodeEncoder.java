/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.securelogging;

import android.graphics.Bitmap;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import java.util.Map;

/**
 * Helper class for encoding barcodes as a Bitmap.
 *
 * <p>Adapted from QRCodeEncoder, from the zxing project: https://github.com/zxing/zxing
 *
 * <p>Licensed under the Apache License, Version 2.0.
 */
public class CrumblesBarcodeEncoder {
  private static final int WHITE = 0xFFFFFFFF;
  private static final int BLACK = 0xFF000000;

  public CrumblesBarcodeEncoder() {}

  public Bitmap createBitmap(BitMatrix matrix) {
    int width = matrix.getWidth();
    int height = matrix.getHeight();
    int[] pixels = new int[width * height];
    for (int y = 0; y < height; y++) {
      int offset = y * width;
      for (int x = 0; x < width; x++) {
        pixels[offset + x] = matrix.get(x, y) ? BLACK : WHITE;
      }
    }

    Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
    bitmap.setPixels(pixels, 0, width, 0, 0, width, height);
    return bitmap;
  }

  public BitMatrix encode(String contents, BarcodeFormat format, int width, int height)
      throws WriterException {
    return encode(contents, format, width, height, null);
  }

  public BitMatrix encode(
      String contents, BarcodeFormat format, int width, int height, Map<EncodeHintType, ?> hints)
      throws WriterException {
    return new MultiFormatWriter().encode(contents, format, width, height, hints);
  }

  public Bitmap encodeBitmap(String contents, BarcodeFormat format, int width, int height)
      throws WriterException {
    return createBitmap(encode(contents, format, width, height));
  }

  public Bitmap encodeBitmap(
      String contents, BarcodeFormat format, int width, int height, Map<EncodeHintType, ?> hints)
      throws WriterException {
    return createBitmap(encode(contents, format, width, height, hints));
  }
}
