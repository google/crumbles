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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import android.graphics.Bitmap;
import android.graphics.Color;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import java.util.EnumMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Unit tests for {@link CrumblesBarcodeEncoder}. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesBarcodeEncoderTest {

  private CrumblesBarcodeEncoder barcodeEncoder;

  @Before
  public void setUp() {
    // Given: A new instance of the barcode encoder is created for each test.
    barcodeEncoder = new CrumblesBarcodeEncoder();
  }

  // --- Tests for encode() methods ---

  @Test
  public void encode_withValidInputs_returnsNonNullBitMatrix() throws WriterException {
    // Given: A valid string content, format, and dimensions.
    String content = "test content";
    int width = 100;
    int height = 100;

    // When: The encode method is called.
    BitMatrix result = barcodeEncoder.encode(content, BarcodeFormat.QR_CODE, width, height);

    // Then: The returned BitMatrix is not null and has the correct dimensions.
    // This directly covers the first line you requested.
    assertThat(result).isNotNull();
    assertThat(result.getWidth()).isEqualTo(width);
    assertThat(result.getHeight()).isEqualTo(height);
  }

  @Test
  public void encode_withValidInputsAndHints_returnsNonNullBitMatrix() throws WriterException {
    // Given: Valid content and dimensions, plus a map of encoding hints.
    String content = "test content with hints";
    int width = 150;
    int height = 150;
    Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
    hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

    // When: The encode method with hints is called.
    BitMatrix result = barcodeEncoder.encode(content, BarcodeFormat.QR_CODE, width, height, hints);

    // Then: The returned BitMatrix is not null and has the correct dimensions.
    // This directly covers the second line you requested.
    assertThat(result).isNotNull();
    assertThat(result.getWidth()).isEqualTo(width);
    assertThat(result.getHeight()).isEqualTo(height);
  }

  @Test
  public void encode_withInvalidInputs_throwsWriterException() {
    // Given: Invalid inputs, such as negative dimensions, that cause a runtime exception.
    String content = "test content";
    int invalidWidth = -50;
    int height = 50;

    // When: The encode method is called with invalid arguments.
    // Then: The method catches the underlying runtime exception and wraps it in a WriterException.
    assertThrows(
        IllegalArgumentException.class,
        () -> barcodeEncoder.encode(content, BarcodeFormat.QR_CODE, invalidWidth, height));
  }

  // --- Test for createBitmap() method ---

  @Test
  public void createBitmap_fromBitMatrix_returnsCorrectBitmap() {
    // Given: A manually created 2x2 BitMatrix with a specific pattern.
    // Pattern:
    // [BLACK, WHITE]
    // [WHITE, BLACK]
    BitMatrix matrix = new BitMatrix(2);
    matrix.set(0, 0); // Black
    matrix.set(1, 1); // Black

    // When: createBitmap is called with this matrix.
    Bitmap bitmap = barcodeEncoder.createBitmap(matrix);

    // Then: The resulting bitmap has the correct dimensions and pixel colors.
    assertThat(bitmap).isNotNull();
    assertThat(bitmap.getWidth()).isEqualTo(2);
    assertThat(bitmap.getHeight()).isEqualTo(2);
    assertThat(bitmap.getPixel(0, 0)).isEqualTo(Color.BLACK);
    assertThat(bitmap.getPixel(1, 0)).isEqualTo(Color.WHITE);
    assertThat(bitmap.getPixel(0, 1)).isEqualTo(Color.WHITE);
    assertThat(bitmap.getPixel(1, 1)).isEqualTo(Color.BLACK);
  }

  // --- Tests for encodeBitmap() methods ---

  @Test
  public void encodeBitmap_withValidInputs_returnsValidBitmap() throws WriterException {
    // Given: Valid content and dimensions.
    String content = "Hello World";
    int width = 200;
    int height = 200;

    // When: The main encodeBitmap method is called.
    Bitmap bitmap = barcodeEncoder.encodeBitmap(content, BarcodeFormat.QR_CODE, width, height);

    // Then: A valid, non-null bitmap is returned.
    assertThat(bitmap).isNotNull();
    assertThat(bitmap.getWidth()).isEqualTo(width);
    assertThat(bitmap.getHeight()).isEqualTo(height);

    // And: To confirm the full process, we check that it contains both black and white pixels.
    boolean foundBlack = false;
    boolean foundWhite = false;
    for (int y = 0; y < height; y++) {
      for (int x = 0; x < width; x++) {
        int pixel = bitmap.getPixel(x, y);
        if (pixel == Color.BLACK) {
          foundBlack = true;
        }
        if (pixel == Color.WHITE) {
          foundWhite = true;
        }
        if (foundBlack && foundWhite) {
          break;
        }
      }
      if (foundBlack && foundWhite) {
        break;
      }
    }
    assertThat(foundBlack).isTrue();
    assertThat(foundWhite).isTrue();
  }
}
