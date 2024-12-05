import { Injectable } from '@nestjs/common';

/**
 * Type representing a schema definition
 * Allows boolean or nested object schema
 */
type SchemaDefinition =
  | boolean
  | {
      [key: string]: SchemaDefinition;
    };

@Injectable()
export class ResponseFormatterService {
  /**
   * Format a single object or array of objects based on the provided schema
   * @param data - Input data (object or array of objects)
   * @param schema - Schema defining which fields to include
   * @returns Filtered data matching the schema
   */
  formatResponse<T = any>(data: T | T[], schema: SchemaDefinition): T | T[] {
    // Handle array input
    if (Array.isArray(data)) {
      return data.map((item) => this.formatObject(item, schema)) as T[];
    }

    // Handle single object input
    return this.formatObject(data, schema);
  }

  /**
   * Recursively format a single object based on the schema
   * @param obj - Input object to format
   * @param schema - Schema defining which fields to include
   * @returns Filtered object
   */
  private formatObject<T = any>(obj: T, schema: SchemaDefinition): T {
    // If obj is not an object or schema is true (include everything), return as-is
    if (typeof obj !== 'object' || obj === null || schema === true) {
      return obj;
    }

    // If schema is false, return empty object
    if (schema === false) {
      return {} as T;
    }

    // Create a new object to store filtered results
    const formattedObj: Partial<T> = {};

    // Iterate through schema keys
    for (const [key, value] of Object.entries(schema)) {
      // If schema is an object (to handle nested schemas)
      if (typeof schema === 'object') {
        // Skip if the key doesn't exist in the original object
        if (!(key in obj)) continue;

        const originalValue = (obj as any)[key];

        // If schema value is boolean
        if (typeof value === 'boolean') {
          if (value) {
            formattedObj[key as keyof T] = originalValue;
          }
          continue;
        }

        // If schema value is an object (nested schema)
        if (typeof value === 'object') {
          // Recursively format nested objects or arrays
          if (Array.isArray(originalValue)) {
            formattedObj[key as keyof T] = originalValue.map((item) =>
              this.formatObject(item, value),
            ) as any;
          } else if (
            typeof originalValue === 'object' &&
            originalValue !== null
          ) {
            formattedObj[key as keyof T] = this.formatObject(
              originalValue,
              value,
            );
          }
        }
      }
    }

    return formattedObj as T;
  }
}
