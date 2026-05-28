import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-leaderboard',
  template: `
    <main class="page">
      <section class="card">
        <h1>🏆 Leaderboard Global</h1>
        <p class="subtitle">Ranking público de mejores puntuaciones de PixelForge Studio.</p>

        <div *ngIf="loading" class="message">Cargando ranking...</div>
        <div *ngIf="errorMessage" class="error">{{ errorMessage }}</div>

        <table *ngIf="!loading && rankings.length">
          <thead>
            <tr>
              <th>#</th>
              <th>Jugador</th>
              <th>Score</th>
              <th>Nivel</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let r of rankings">
              <td>{{ r.position }}</td>
              <td>{{ r.nickname }}</td>
              <td>{{ r.score }}</td>
              <td>{{ r.level_reached }}</td>
            </tr>
          </tbody>
        </table>

        <div *ngIf="!loading && !rankings.length && !errorMessage" class="message">
          Todavía no hay puntuaciones registradas.
        </div>

        <p class="footnote">
          API conectada a: {{ apiUrl }}
        </p>
      </section>
    </main>
  `,
  styles: [`
    .page {
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      padding: 48px 20px;
      background: #101018;
      color: #ffffff;
    }

    .card {
      width: min(900px, 100%);
      background: #1f1f2e;
      border-radius: 18px;
      padding: 32px;
      box-shadow: 0 18px 45px rgba(0, 0, 0, 0.35);
    }

    h1 {
      margin: 0 0 8px;
      color: #7dd3fc;
      font-size: 32px;
    }

    .subtitle {
      margin: 0 0 24px;
      color: #cbd5e1;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 12px;
    }

    th, td {
      padding: 14px 16px;
      border-bottom: 1px solid #334155;
      text-align: left;
    }

    th {
      background: #0f172a;
      color: #93c5fd;
      font-weight: 700;
    }

    tr:hover td {
      background: #273449;
    }

    .message {
      padding: 18px;
      background: #0f172a;
      border-radius: 12px;
      color: #cbd5e1;
    }

    .error {
      padding: 18px;
      background: #7f1d1d;
      border-radius: 12px;
      color: #fee2e2;
      margin-bottom: 16px;
    }

    .footnote {
      margin-top: 22px;
      color: #94a3b8;
      font-size: 13px;
    }
  `]
})
export class LeaderboardComponent implements OnInit {
  rankings: any[] = [];
  loading = true;
  errorMessage = '';
  apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.http.get<any>(`${environment.apiUrl}/leaderboard?page=1&limit=10`)
      .subscribe({
        next: (data) => {
          this.rankings = data.rankings || [];
          this.loading = false;
        },
        error: () => {
          this.errorMessage = 'No fue posible cargar el leaderboard.';
          this.loading = false;
        }
      });
  }
}
