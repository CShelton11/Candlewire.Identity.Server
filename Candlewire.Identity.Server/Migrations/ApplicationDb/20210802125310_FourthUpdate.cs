using Microsoft.EntityFrameworkCore.Migrations;

namespace Candlewire.Identity.Server.Migrations.ApplicationDb
{
    public partial class FourthUpdate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AspNetRoleClients_AspNetRoles_ApplicationRoleId",
                table: "AspNetRoleClients");

            migrationBuilder.DropForeignKey(
                name: "FK_AspNetRoleMaps_AspNetRoles_ApplicationRoleId",
                table: "AspNetRoleMaps");

            migrationBuilder.DropIndex(
                name: "IX_AspNetRoleMaps_ApplicationRoleId",
                table: "AspNetRoleMaps");

            migrationBuilder.DropIndex(
                name: "IX_AspNetRoleClients_ApplicationRoleId",
                table: "AspNetRoleClients");

            migrationBuilder.DropColumn(
                name: "ApplicationRoleId",
                table: "AspNetRoleMaps");

            migrationBuilder.DropColumn(
                name: "ApplicationRoleId",
                table: "AspNetRoleClients");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ApplicationRoleId",
                table: "AspNetRoleMaps",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ApplicationRoleId",
                table: "AspNetRoleClients",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleMaps_ApplicationRoleId",
                table: "AspNetRoleMaps",
                column: "ApplicationRoleId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClients_ApplicationRoleId",
                table: "AspNetRoleClients",
                column: "ApplicationRoleId");

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetRoleClients_AspNetRoles_ApplicationRoleId",
                table: "AspNetRoleClients",
                column: "ApplicationRoleId",
                principalTable: "AspNetRoles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetRoleMaps_AspNetRoles_ApplicationRoleId",
                table: "AspNetRoleMaps",
                column: "ApplicationRoleId",
                principalTable: "AspNetRoles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
