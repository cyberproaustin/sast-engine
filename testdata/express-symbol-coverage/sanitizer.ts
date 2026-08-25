/** Stands in for Angular's DomSanitizer, whose one escape hatch is named so plainly that
    reaching it is a statement of intent. */
export const sanitizer = {
  bypassSecurityTrustHtml: (value: string) => value,
};
