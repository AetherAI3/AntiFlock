import Link from "next/link";

export default function NotFound() {
  return (
    <div className="error-state" role="alert">
      <p className="eyebrow">Route not found</p>
      <h2>This Third-Eye view does not exist</h2>
      <p>Return to the protection overview or use the primary navigation.</p>
      <Link className="button button-primary" href="/">Return to overview</Link>
    </div>
  );
}
